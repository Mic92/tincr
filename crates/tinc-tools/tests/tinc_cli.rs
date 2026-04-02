//! Integration tests for the `tinc` binary. Spawns it as a subprocess
//! via `CARGO_BIN_EXE_tinc`, same pattern as `self_roundtrip.rs`.
//!
//! ## What this proves over the unit tests in `cmd/init.rs`
//!
//! The unit tests call `cmd::init::run()` directly. They prove the
//! *function* works. They don't prove:
//!
//! - argv parsing (`-c` / `-n` / `--config=` glued form)
//! - the dispatch table finds `init`
//! - exit codes (success → 0, error → 1)
//! - error messages go to stderr, not stdout
//!
//! Those are the binary's job. Test the binary.
//!
//! ## Cross-impl: `tinc init` → C `sptps_test`
//!
//! `cross_init_key_loads_in_c` is the load-bearing test. It runs
//! `tinc init`, then takes the resulting `ed25519_key.priv` and uses
//! it as input to the *C* `sptps_test`. If the C binary can establish
//! an SPTPS session with that key, the PEM format and the 96-byte
//! blob layout are correct end-to-end.
//!
//! Why this matters more than `cross_pem_read` in `self_roundtrip.rs`:
//! that test uses keys from `sptps_keypair`, which writes PEM to a
//! standalone `.priv` file. `tinc init` writes the *same* PEM but
//! through a different code path (`cmd::init` uses `write_pem`
//! directly with mode 0600 + `O_EXCL`, not `keypair::write_pair`).
//! Same format, different writer — a future refactor that breaks one
//! but not the other would slip through `cross_pem_read` but get
//! caught here.

#![allow(clippy::doc_markdown)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin(name: &str) -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_tinc") {
        // The env var Cargo sets is per-binary. Map name → var.
        // We only have three; hardcode.
        let var = match name {
            "tinc" => "CARGO_BIN_EXE_tinc",
            "sptps_test" => "CARGO_BIN_EXE_sptps_test",
            "sptps_keypair" => "CARGO_BIN_EXE_sptps_keypair",
            _ => panic!("unknown bin {name}"),
        };
        if let Ok(p) = std::env::var(var) {
            return PathBuf::from(p);
        }
        // Fall through to the path-based fallback.
        let _ = p;
    }
    // CARGO_BIN_EXE_* not set (rare; cargo always sets it for [[bin]]s
    // of the crate-under-test). Derive from the test binary's location:
    // tests run from target/{profile}/deps/, binaries are in
    // target/{profile}/.
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(name)
}

/// Run `tinc` with args, capture everything.
fn tinc(args: &[&str]) -> std::process::Output {
    Command::new(bin("tinc"))
        .args(args)
        // NETNAME from the parent env would change confbase resolution.
        // Strip it so tests are hermetic. We *do* test the env var, but
        // explicitly (by passing `.env("NETNAME", ...)` in that test).
        .env_remove("NETNAME")
        .output()
        .expect("spawn tinc")
}

/// Run `tinc` with an extra env var. For NETNAME tests.
fn tinc_with_env(env: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin("tinc"));
    cmd.args(args).env_remove("NETNAME");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn tinc")
}

/// Run `tinc` with stdin fed from a byte slice. For `import`/`exchange`.
fn tinc_stdin(args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(bin("tinc"))
        .args(args)
        .env_remove("NETNAME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tinc");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    // Drop closes the pipe → child sees EOF → import loop ends.
    child.wait_with_output().expect("wait tinc")
}

// ────────────────────────────────────────────────────────────────────
// export / import / exchange through the binary
// ────────────────────────────────────────────────────────────────────

/// `tinc init` then `tinc generate-ed25519-keys`. Basic plumbing:
/// the new key is live, the old one is `#`-commented in both files.
#[test]
fn genkey_after_init() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    // Snapshot pre-rotation.
    let priv_before = std::fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
    let host_before = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert!(!priv_before.contains('#'), "init writes a clean PEM");
    assert!(!host_before.contains('#'));

    // Rotate.
    let out = tinc(&["-c", cb, "generate-ed25519-keys"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Generating Ed25519 key pair"));
    assert!(stderr.contains("Done."));

    // ─── private key file: one #-block, one live block ──────────
    let priv_after = std::fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
    // The old block is the first half, #-prefixed. Check by rough
    // shape: every line that was in priv_before is in priv_after
    // with `#` prepended.
    for line in priv_before.lines() {
        assert!(
            priv_after.contains(&format!("#{line}\n")),
            "old line {line:?} not commented in {priv_after:?}"
        );
    }
    // Exactly one live BEGIN (no leading #).
    assert_eq!(priv_after.matches("\n-----BEGIN ").count(), 1);
    // Two BEGINs total (one #, one live). The first one starts the
    // file (no preceding \n), so count both forms.
    let total_begins = priv_after.matches("-----BEGIN ED25519").count();
    assert_eq!(total_begins, 2);

    // ─── host file: one #Ed25519PublicKey, one live one ─────────
    let host_after = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert_eq!(host_after.matches("#Ed25519PublicKey").count(), 1);
    // Live line: starts at beginning-of-line with no #.
    let live_count = host_after
        .lines()
        .filter(|l| l.starts_with("Ed25519PublicKey"))
        .count();
    assert_eq!(live_count, 1);
    // The live one is *different* from the old one. (Tests that
    // genkey actually generates fresh entropy, not... I don't know,
    // re-reads and re-appends. Paranoia.)
    let new_b64 = host_after
        .lines()
        .find(|l| l.starts_with("Ed25519PublicKey"))
        .unwrap();
    assert!(!host_before.contains(new_b64));
}

/// genkey without init → fails (no tinc.conf, can't `get_my_name`).
/// The C falls back to `ed25519_key.pub` PEM in this case; we don't.
/// See `cmd/genkey.rs` module doc.
#[test]
fn genkey_no_config() {
    let dir = tempfile::tempdir().unwrap();
    let out = tinc(&["-c", dir.path().to_str().unwrap(), "generate-ed25519-keys"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tinc.conf"));
}

/// genkey rejects extra args. C `tincctl.c:2354`.
#[test]
fn genkey_too_many_args() {
    let dir = tempfile::tempdir().unwrap();
    let out = tinc(&[
        "-c",
        dir.path().to_str().unwrap(),
        "generate-ed25519-keys",
        "extra",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Too many arguments"));
}

/// **The contract test for rotation.** init, then genkey, then prove
/// the *rotated* key still works for SPTPS. Uses `keypair::read_private`
/// (the same loader the daemon will use) to read past the `#`-block.
///
/// This is what `rotation_roundtrip` in `genkey.rs` proves at the
/// unit level; this proves it at the binary level (the actual
/// `ed25519_key.priv` written by the actual `tinc` binary).
#[test]
fn genkey_rotated_key_loads() {
    use tinc_tools::keypair;

    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());
    let out = tinc(&["-c", cb, "generate-ed25519-keys"]);
    assert!(out.status.success(), "{out:?}");

    // ─── read_private skips the #-block, returns the live key ───
    let priv_path = confbase.join("ed25519_key.priv");
    let sk = keypair::read_private(&priv_path).expect("read past #-block");

    // ─── the live pubkey in hosts/alice matches sk.public_key() ──
    // This proves: (1) the live PEM is the *new* key not the old one,
    // (2) the live config line is the *new* pubkey not the old one,
    // (3) they're a coherent pair.
    let host = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    let live_line = host
        .lines()
        .find(|l| l.starts_with("Ed25519PublicKey = "))
        .expect("live pubkey line");
    let b64 = live_line.strip_prefix("Ed25519PublicKey = ").unwrap();
    let pubkey = tinc_crypto::b64::decode(b64).expect("tinc-b64 decode");
    assert_eq!(&pubkey[..], &sk.public_key()[..]);
}

/// Mode preservation through rotation. The 0600 from init survives
/// disable_old_keys's tmpfile rename.
#[cfg(unix)]
#[test]
fn genkey_preserves_priv_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    // init sets 0600 (verified in `init`'s tests). Rotate.
    let out = tinc(&["-c", cb, "generate-ed25519-keys"]);
    assert!(out.status.success());

    let mode = std::fs::metadata(confbase.join("ed25519_key.priv"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

/// **The contract test for sign/verify.** init → sign → verify, all
/// through the binary. `verify .` (`.` = own name) on a sign output
/// emits the original body byte-exact to stdout.
#[test]
fn sign_verify_roundtrip_binary() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    let payload = dir.path().join("payload");
    let data = b"hello world\nbinary: \x00\xff\n";
    std::fs::write(&payload, data).unwrap();

    // ─── sign ───────────────────────────────────────────────────────
    let out = tinc(&["-c", cb, "sign", payload.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    let signed = out.stdout;

    // Header shape. First line, `Signature = alice <time> <86b64>`.
    // Time is non-deterministic (`SystemTime::now()`); just check
    // structure.
    let nl = signed.iter().position(|&b| b == b'\n').unwrap();
    let header = std::str::from_utf8(&signed[..nl]).unwrap();
    let mut fields = header.split(' ');
    assert_eq!(fields.next(), Some("Signature"));
    assert_eq!(fields.next(), Some("="));
    assert_eq!(fields.next(), Some("alice"));
    let t: i64 = fields.next().unwrap().parse().unwrap();
    assert!(t > 1_700_000_000); // sanity: signed after Nov 2023
    assert_eq!(fields.next().unwrap().len(), 86);
    assert!(fields.next().is_none());

    // Body is the original, byte-exact.
    assert_eq!(&signed[nl + 1..], data);

    // ─── verify (file arg) ──────────────────────────────────────────
    let signed_path = dir.path().join("signed");
    std::fs::write(&signed_path, &signed).unwrap();
    let out = tinc(&["-c", cb, "verify", ".", signed_path.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    // stdout is the body, byte-exact.
    assert_eq!(out.stdout, data);

    // ─── verify (stdin) ─────────────────────────────────────────────
    let out = tinc_stdin(&["-c", cb, "verify", "."], &signed);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // ─── verify with `*` (any signer) ───────────────────────────────
    let out = tinc_stdin(&["-c", cb, "verify", "*"], &signed);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // ─── verify with explicit name ──────────────────────────────────
    let out = tinc_stdin(&["-c", cb, "verify", "alice"], &signed);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // ─── verify with WRONG name → fail ─────────────────────────────
    let out = tinc_stdin(&["-c", cb, "verify", "bob"], &signed);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Signature is not made by bob"));
    // No body output on failure.
    assert!(out.stdout.is_empty());
}

/// sign reads stdin when no file arg. Then verify reads stdin too.
/// `tinc sign | tinc verify .` is the canonical pipeline.
#[test]
fn sign_stdin_verify_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    let data = b"stdin data\n";
    let signed = tinc_stdin(&["-c", cb, "sign"], data);
    assert!(signed.status.success(), "{signed:?}");

    let verified = tinc_stdin(&["-c", cb, "verify", "."], &signed.stdout);
    assert!(verified.status.success(), "{verified:?}");
    assert_eq!(verified.stdout, data);
}

/// Tampered body → verify fails. Integration-level repeat of the
/// unit test, proves the binary plumbing carries the error through.
#[test]
fn sign_verify_tamper_detected() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    let signed = tinc_stdin(&["-c", cb, "sign"], b"untampered");
    assert!(signed.status.success());

    // Tamper: change one body byte.
    let mut tampered = signed.stdout;
    *tampered.last_mut().unwrap() ^= 1;

    let out = tinc_stdin(&["-c", cb, "verify", "."], &tampered);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Invalid signature"));
    assert!(out.stdout.is_empty());
}

/// verify with no signer arg → "No signer given!" (MissingArg).
/// C `tincctl.c:2860`.
#[test]
fn verify_no_signer_arg() {
    let dir = tempfile::tempdir().unwrap();
    let out = tinc(&["-c", dir.path().to_str().unwrap(), "verify"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No signer given"));
}

/// sign without init → fails (no tinc.conf).
#[test]
fn sign_no_config() {
    let dir = tempfile::tempdir().unwrap();
    let out = tinc(&["-c", dir.path().to_str().unwrap(), "sign"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tinc.conf"));
}

/// **Cross-node verify.** alice signs, bob verifies (with
/// `hosts/alice` in bob's confbase). This is the actual deployment
/// pattern: sign on one machine, ship the signed file, verify on
/// another. Uses `*` signer mode (bob doesn't know in advance who
/// signed it; trusts hosts/ as keyring).
#[test]
fn sign_verify_cross_node() {
    let dir = tempfile::tempdir().unwrap();
    let alice_base = dir.path().join("alice");
    let bob_base = dir.path().join("bob");

    let out = tinc(&["-c", alice_base.to_str().unwrap(), "init", "alice"]);
    assert!(out.status.success());
    let out = tinc(&["-c", bob_base.to_str().unwrap(), "init", "bob"]);
    assert!(out.status.success());

    // Ship alice's host file to bob (this is what export|import does;
    // here we just copy).
    std::fs::copy(alice_base.join("hosts/alice"), bob_base.join("hosts/alice")).unwrap();

    // alice signs.
    let data = b"cross-node payload";
    let signed = tinc_stdin(&["-c", alice_base.to_str().unwrap(), "sign"], data);
    assert!(signed.status.success());

    // bob verifies with `*`.
    let out = tinc_stdin(
        &["-c", bob_base.to_str().unwrap(), "verify", "*"],
        &signed.stdout,
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // bob verifies with explicit `alice` (he knows who should have
    // signed it).
    let out = tinc_stdin(
        &["-c", bob_base.to_str().unwrap(), "verify", "alice"],
        &signed.stdout,
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);
}

/// `tinc init` then `tinc export`. Basic plumbing.
#[test]
fn export_after_init() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    let out = tinc(&["-c", cb, "export"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The injected Name = line.
    assert!(stdout.starts_with("Name = alice\n"));
    // The Ed25519PublicKey line that init wrote to hosts/alice.
    assert!(stdout.contains("Ed25519PublicKey = "));
    // Nothing on stderr (no errors, no progress messages).
    assert!(out.stderr.is_empty());
}

/// `export` without `init` first → fails (no tinc.conf, can't get_my_name).
#[test]
fn export_no_config() {
    let dir = tempfile::tempdir().unwrap();
    let out = tinc(&["-c", dir.path().to_str().unwrap(), "export"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tinc.conf"));
}

/// `tinc import` reads a blob from stdin, writes hosts/NAME.
#[test]
fn import_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    // init first — import needs hosts_dir to exist.
    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    let blob = b"Name = bob\nSubnet = 10.0.2.0/24\nAddress = 192.0.2.2\n";
    let out = tinc_stdin(&["-c", cb, "import"], blob);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Imported 1 host"));

    let written = std::fs::read_to_string(confbase.join("hosts/bob")).unwrap();
    assert_eq!(written, "Subnet = 10.0.2.0/24\nAddress = 192.0.2.2\n");
}

/// `import` skips existing without `--force`, overwrites with.
#[test]
fn import_force_flag() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    // alice's hosts file exists (init wrote it). Import a new alice.
    let blob = b"Name = alice\nOVERWRITTEN\n";

    // Without --force: skip, exit 1 (count==0).
    let out = tinc_stdin(&["-c", cb, "import"], blob);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("already exists"));
    assert!(stderr.contains("No host configuration files imported"));
    // Original contents intact (still has the Ed25519PublicKey from init).
    let content = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert!(content.contains("Ed25519PublicKey"));

    // With --force: overwrite.
    let out = tinc_stdin(&["--force", "-c", cb, "import"], blob);
    assert!(out.status.success(), "{out:?}");
    let content = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert_eq!(content, "OVERWRITTEN\n");
}

/// `import` with empty stdin → exit 1, "No host... imported."
#[test]
fn import_empty() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();
    let out = tinc(&["-c", cb, "init", "alice"]);
    assert!(out.status.success());

    let out = tinc_stdin(&["-c", cb, "import"], b"");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No host configuration files imported"));
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
/// C `sscanf("Name = %s")`. Tested by feeding Rust export output back
/// into Rust import (above) AND by checking the format manually here.
///
/// We can't easily run C `tinc import` (no C `tinc` binary in the
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
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out = tinc(&["-c", cb, "init", "node1"]);
    assert!(out.status.success());

    let out = tinc(&["-c", cb, "export"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();

    // The exact byte sequence C `sscanf("Name = %s")` matches.
    // Uppercase N, space, equals, space.
    let first_line = stdout.lines().next().unwrap();
    assert_eq!(first_line, "Name = node1");
    // sscanf %s stops at whitespace; node1 has none.
    // The literal-space-equals-space is mandatory in the format string.
    // Any other format (`Name=node1`, ` Name = node1`) wouldn't match.
}

// ────────────────────────────────────────────────────────────────────
// Argv parsing & dispatch
// ────────────────────────────────────────────────────────────────────

#[test]
fn help_exits_zero() {
    let out = tinc(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Usage: tinc"));
    assert!(stdout.contains("init NAME"));
    // Help goes to stdout, not stderr. C does this; `man` convention.
    assert!(out.stderr.is_empty());
}

#[test]
fn version_exits_zero() {
    let out = tinc(&["--version"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("tinc"));
    assert!(stdout.contains("(Rust)"));
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

// ────────────────────────────────────────────────────────────────────
// `tinc init` through the binary
// ────────────────────────────────────────────────────────────────────

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
    let dir = tempfile::tempdir().unwrap();
    let out = tinc(&["-c", dir.path().to_str().unwrap(), "init"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No Name given"));
    // Nothing created — arity check fires before any filesystem op.
    assert!(!dir.path().join("tinc.conf").exists());
}

#[test]
fn init_too_many_args() {
    let dir = tempfile::tempdir().unwrap();
    let out = tinc(&["-c", dir.path().to_str().unwrap(), "init", "alice", "bob"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Too many arguments"));
}

#[test]
fn init_bad_name() {
    let dir = tempfile::tempdir().unwrap();
    // Dash is not in `check_id`'s allowed set.
    let out = tinc(&["-c", dir.path().to_str().unwrap(), "init", "has-dash"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Invalid Name"));
}

#[test]
fn init_reinit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let cb = confbase.to_str().unwrap();

    let out1 = tinc(&["-c", cb, "init", "alice"]);
    assert!(out1.status.success());

    let out2 = tinc(&["-c", cb, "init", "bob"]);
    assert!(!out2.status.success());
    let stderr = String::from_utf8(out2.stderr).unwrap();
    assert!(stderr.contains("already exists"));
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

// ────────────────────────────────────────────────────────────────────
// NETNAME env var
// ────────────────────────────────────────────────────────────────────

/// `NETNAME` from env reaches `Paths::for_cli`. C: `tincctl.c:258-263`.
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
/// wasn't being read, `netname` would be `None` (we env_remove'd it
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
    // `NETNAME=.` means "no netname" — `tincctl.c:267-270`. With `-c`
    // also given, the netname resolution doesn't matter (confbase
    // wins), but we shouldn't get the "Both netname and config given"
    // warning either, because `.` was normalized to None *before* the
    // both-given check... wait, no. The C does the both-given check
    // in `make_names`, the `.` normalization in `parse_options`.
    // `parse_options` runs first. So `NETNAME=. tinc -c /tmp/x init`
    // sees netname=None confbase=/tmp/x → no warning.
    //
    // Our `for_cli` does the both-check; our `parse_global_options`
    // does the `.` normalization. Same order. Confirm: no warning.
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

#[test]
fn netname_traversal_rejected() {
    let out = tinc_with_env(&[("NETNAME", "../escape")], &["init", "alice"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Invalid character in netname"));
}

// ────────────────────────────────────────────────────────────────────
// Cross-impl: `tinc init` key loads in C `sptps_test`
// ────────────────────────────────────────────────────────────────────

/// Run `tinc init`, take the resulting private key, hand it to the C
/// `sptps_test`. If the C binary can complete a handshake with that
/// key, the PEM format and blob layout are correct end-to-end.
///
/// The test setup is the same shape as `self_roundtrip.rs::scenario` —
/// server listens, client connects, push bytes, diff. The difference:
/// the *key files* come from `tinc init`, not `sptps_keypair`.
///
/// Why both ends use init-generated keys: maximizes coverage. C-server
/// loads alice's private key (PEM read), C-client loads alice's
/// *public* key from a synthesized PEM file (we extract it from
/// `hosts/alice` and re-wrap). Both directions of the format.
#[test]
#[cfg(unix)]
fn cross_init_key_loads_in_c() {
    let Some(c_sptps_test) = std::env::var_os("TINC_C_SPTPS_TEST").map(PathBuf::from) else {
        eprintln!("SKIP: TINC_C_SPTPS_TEST not set");
        return;
    };

    let dir = tempfile::tempdir().unwrap();

    // Two confbases — alice and bob — so we have two distinct keypairs.
    // Real tinc deployment shape.
    let alice_base = dir.path().join("alice");
    let bob_base = dir.path().join("bob");

    let out = tinc(&["-c", alice_base.to_str().unwrap(), "init", "alice"]);
    assert!(out.status.success(), "{out:?}");
    let out = tinc(&["-c", bob_base.to_str().unwrap(), "init", "bob"]);
    assert!(out.status.success(), "{out:?}");

    // The private keys are PEM files — sptps_test reads them directly.
    let alice_priv = alice_base.join("ed25519_key.priv");
    let bob_priv = bob_base.join("ed25519_key.priv");

    // The *public* keys are config lines in hosts/NAME, not PEM files.
    // sptps_test wants PEM. Extract the b64, decode (tinc LSB-first),
    // re-wrap as PEM. This is what a peer would do when reading a
    // host file: `get_config_string("Ed25519PublicKey")` →
    // `ecdsa_set_base64_public_key` → key in memory. We replicate that
    // pipeline, then dump back to PEM for sptps_test.
    let alice_pub = extract_pubkey_to_pem(&alice_base.join("hosts/alice"), dir.path(), "alice");
    let bob_pub = extract_pubkey_to_pem(&bob_base.join("hosts/bob"), dir.path(), "bob");

    // ─── Now the actual SPTPS handshake. C both sides. ─────────────
    // alice serves (responder), bob connects (initiator).
    // This is the `self_roundtrip.rs` choreography, inlined and
    // simplified (we don't need the full Impl matrix here, just C↔C
    // with init-generated keys).

    let mut server = Command::new(&c_sptps_test)
        .arg("-4")
        .arg("-r")
        .arg(&alice_priv)
        .arg(&bob_pub)
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn C server");

    let mut server_stderr = server.stderr.take().unwrap();
    let port = wait_for_port(&mut server_stderr);

    let mut client = Command::new(&c_sptps_test)
        .arg("-4")
        .arg("-q")
        .arg(&bob_priv)
        .arg(&alice_pub)
        .arg("localhost")
        .arg(port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn C client");

    // Push 256 bytes.
    let data: Vec<u8> = (0..=255).collect();
    {
        let mut stdin = client.stdin.take().unwrap();
        stdin.write_all(&data).unwrap();
    }

    // Read it back from the server.
    let mut server_stdout = server.stdout.take().unwrap();
    let mut received = vec![0u8; data.len()];
    let mut got = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while got < data.len() {
        assert!(
            std::time::Instant::now() < deadline,
            "timeout reading server stdout (got {got}/{})",
            data.len()
        );
        let n = server_stdout.read(&mut received[got..]).unwrap();
        assert!(n != 0, "server stdout EOF after {got} bytes");
        got += n;
    }

    // The proof.
    assert_eq!(received, data, "C↔C handshake with tinc-init keys");

    // Cleanup. Stream mode → server exits on TCP FIN.
    let client_status = client.wait().unwrap();
    assert!(client_status.success(), "client: {client_status:?}");

    // Hold stderr open until server exits (SIGPIPE footgun — see
    // self_roundtrip.rs `wait_for_port` doc).
    let drain = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = server_stderr.read_to_end(&mut sink);
    });
    let server_status = server.wait().unwrap();
    let _ = drain.join();
    assert!(server_status.success(), "server: {server_status:?}");
}

/// Read `Ed25519PublicKey = <b64>` from a host file, decode the
/// tinc-b64, re-wrap as PEM. This is the `ecdsa_set_base64_public_key`
/// → `ecdsa_write_pem_public_key` pipeline, manually.
#[cfg(unix)]
fn extract_pubkey_to_pem(host_file: &Path, out_dir: &Path, name: &str) -> PathBuf {
    let contents = std::fs::read_to_string(host_file).unwrap();
    // Parse: `Ed25519PublicKey = <b64>\n`. We could use tinc-conf's
    // parser here, but the format is simple enough that string ops
    // suffice and don't pull in another dependency for the test.
    let b64 = contents
        .lines()
        .find_map(|l| l.strip_prefix("Ed25519PublicKey = "))
        .expect("host file has Ed25519PublicKey line");

    // tinc LSB-first b64 → 32 bytes.
    let pubkey = tinc_crypto::b64::decode(b64).expect("valid tinc-b64");
    assert_eq!(pubkey.len(), 32);

    // Re-wrap as PEM. `sptps_test` calls `ecdsa_read_pem_public_key`
    // which expects `-----BEGIN ED25519 PUBLIC KEY-----`.
    let out_path = out_dir.join(format!("{name}.pub"));
    let f = std::fs::File::create(&out_path).unwrap();
    let mut w = std::io::BufWriter::new(f);
    tinc_conf::pem::write_pem(&mut w, "ED25519 PUBLIC KEY", &pubkey).unwrap();

    out_path
}

/// Parse `Listening on PORT...` from stderr. Same as `self_roundtrip.rs`.
/// Takes `&mut` so the caller keeps stderr alive (SIGPIPE — see that
/// file's `wait_for_port` doc, hard-won lesson).
#[cfg(unix)]
fn wait_for_port(stderr: &mut impl Read) -> u16 {
    let mut buf = Vec::new();
    let mut byte = [0u8];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "timeout waiting for 'Listening on'; got: {}",
            String::from_utf8_lossy(&buf)
        );
        let n = stderr.read(&mut byte).unwrap();
        assert!(
            n != 0,
            "stderr EOF before 'Listening on'; got: {}",
            String::from_utf8_lossy(&buf)
        );
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            let line = String::from_utf8_lossy(&buf);
            if let Some(rest) = line.strip_prefix("Listening on ") {
                let port_str = rest.trim_end_matches("...\n");
                return port_str.parse().unwrap();
            }
            buf.clear();
        }
    }
}
