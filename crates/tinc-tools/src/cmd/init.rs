//! `tinc init NAME`.
//!
//! ## What it does
//!
//! Bootstraps a fresh confbase. After `tinc -n myvpn init alice`:
//! ```text
//! /etc/tinc/myvpn/
//!   tinc.conf              # "Name = alice\n"
//!   ed25519_key.priv       # PEM, mode 0600
//!   tinc-up                # stub script, mode 0755
//!   hosts/
//!     alice                # "Ed25519PublicKey = <b64>\n"
//!   cache/                 # empty
//! ```
//!
//! That's it. Five files/dirs. The user then `tinc edit tinc.conf` to
//! add `ConnectTo`, runs `tinc-up` setup, and `tincd` is good to go.
//!
//! ## Intentional deviations from upstream
//!
//! Deliberate, not bugs to fix later.
//!
//! - **No interactive name prompt.** The prompt only exists for the
//!   interactive `tinc> ` shell mode, which we don't have. When shell
//!   mode lands the prompt becomes a shell-layer concern.
//! - **No `check_port`.** Upstream tries to bind 655 and picks a
//!   random high port if busy. Dropped: pulls in socket code, and the
//!   random pick is often wrong (firewall/NAT). Better to fail loudly
//!   at first daemon start.
//! - **No RSA keygen.** `DISABLE_LEGACY` is permanently on.
//!
//! ## File mode subtlety
//!
//! `OpenOptions::mode(0o600)` for the key (umask only clears bits,
//! never widens) plus `set_permissions(0o755)` for tinc-up. With
//! umask 077, tinc-up ends up 0755 instead of 0700; the security-
//! relevant file (the key) is unaffected.
//!
//! ## Idempotency: NO
//!
//! `tinc init` on an existing confbase fails (`tinc.conf already
//! exists`). Re-init would overwrite the private key. No rollback on
//! partial failure — disk full / perm flip mid-init is rare.

use std::fs;
use std::io::Write;

use crate::cmd::{CmdError, OpenKind, io_err, write_private_key};
use crate::keypair;
use crate::names::{Paths, check_id};

use tinc_crypto::b64;

/// `cmd_init`. Takes the resolved `Paths` and the node name from argv.
///
/// Progress goes to stderr. Stdout is reserved for command *output*
/// (export does this); progress chatter is diagnostics.
///
/// # Errors
///
/// `Exists` if `tinc.conf` already exists. `BadInput` if the name fails
/// `check_id`. `Io` for any filesystem failure (mkdir, open, write,
/// chmod) — the path tells you which.
///
/// Doesn't roll back on partial failure. See module doc.
pub fn run(paths: &Paths, name: &str) -> Result<(), CmdError> {
    // ─── Guard: already initialized?
    // `try_exists` not `exists`: `exists` swallows EACCES (returns
    // false on permission-denied to the parent dir), and we'd rather
    // surface that as `Io` than silently re-init.
    let tinc_conf = paths.tinc_conf();
    match tinc_conf.try_exists() {
        Ok(true) => return Err(CmdError::Exists(tinc_conf)),
        Ok(false) => {}
        // EACCES here means the *parent* exists but is unreadable
        // (e.g. `/etc/tinc` mode 0700 root). The raw errno is
        // correct but unhelpful; add the `-c DIR` hint so
        // first-run-as-user isn't a dead end.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(eacces_hint(&tinc_conf, &e));
        }
        Err(e) => return Err(io_err(&tinc_conf)(e)),
    }

    if !check_id(name) {
        return Err(CmdError::BadInput(
            "Invalid Name! Only a-z, A-Z, 0-9 and _ are allowed.".into(),
        ));
    }

    // ─── makedirs
    // The common non-root failure is here (not `try_exists` above):
    // `/etc/tinc` typically doesn't exist yet, so the *mkdir* is what
    // hits EACCES.
    if let Some(confdir) = &paths.confdir {
        makedir(confdir, 0o755).map_err(|e| hint_on_eacces(confdir, e))?;
    }
    makedir(&paths.confbase, 0o755).map_err(|e| hint_on_eacces(&paths.confbase, e))?;
    makedir(&paths.hosts_dir(), 0o755)?;
    makedir(&paths.cache_dir(), 0o755)?;

    // ─── Write tinc.conf
    // No `O_EXCL` — we already checked `try_exists` above. There's a
    // TOCTOU here (check, then someone-else-creates, then we
    // overwrite), but the threat model doesn't include hostile
    // concurrent `tinc init`s.
    {
        let mut f = super::create_nofollow(&tinc_conf)?;
        writeln!(f, "Name = {name}").map_err(io_err(&tinc_conf))?;
    }

    // ─── Generate Ed25519 keypair
    // Private → PEM (daemon reads it); public → config *line* in
    // `hosts/NAME` (NOT a PEM — *peers* read it via the config parser).
    eprintln!("Generating Ed25519 key pair:");
    let sk = keypair::generate();
    eprintln!("Done.");

    // Private: PEM, 0600, `O_EXCL` — clobbering an existing key loses
    // identity to existing peers.
    write_private_key(&paths.ed25519_private(), &sk, OpenKind::CreateExcl)?;

    // Public: config line in `hosts/NAME`. The b64 is tinc's LSB-first
    // variant — `b64::encode`, NOT standard base64. Standard b64 here
    // would fail to round-trip on the peer side and the key would be
    // rejected. Highest-stakes line in the file.
    //
    // Append mode: `cmd_init` is the first writer but `check_port`
    // (when we add it) appends `Port = N` to the same file.
    {
        let host_path = paths.host_file(name);
        let mut f = super::open_nofollow(&host_path, super::OpenKind::Append, 0o666)?;
        let pubkey_b64 = b64::encode(sk.public_key());
        writeln!(f, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_path))?;
    }

    // ─── tinc-up stub (Unix only)
    #[cfg(unix)]
    write_tinc_up_placeholder(paths)?;

    Ok(())
}

/// Create the `tinc-up` stub at mode 0755 if it doesn't already exist.
/// Returns the path when written so `join` can record it for rollback.
///
/// Upstream's stub suggests `ifconfig`; we suggest iproute2 so a user
/// who uncomments the example doesn't hit `command not found`.
#[cfg(unix)]
pub(crate) fn write_tinc_up_placeholder(
    paths: &Paths,
) -> Result<Option<std::path::PathBuf>, CmdError> {
    use std::os::unix::fs::PermissionsExt;
    let up_path = paths.tinc_up();
    // `try_exists` then `O_EXCL`: belt-and-suspenders, but lets us
    // silently skip instead of erroring on EEXIST.
    if up_path.try_exists().map_err(io_err(&up_path))? {
        return Ok(None);
    }
    let mut f = super::open_nofollow(&up_path, OpenKind::CreateExcl, 0o755)?;
    f.write_all(
        b"#!/bin/sh\n\
          \n\
          echo 'Unconfigured tinc-up script, please edit '$0'!'\n\
          \n\
          #ip link set dev $INTERFACE up\n\
          #ip addr add <your-vpn-ip>/<prefixlen> dev $INTERFACE\n",
    )
    .map_err(io_err(&up_path))?;
    // Explicit chmod: umask may have stripped the x bit from the create mode.
    fs::set_permissions(&up_path, fs::Permissions::from_mode(0o755)).map_err(io_err(&up_path))?;
    Ok(Some(up_path))
}

/// Wrap an EACCES from confbase creation with a hint pointing at
/// `-c DIR`. The bare "Could not access /etc/tinc: Permission denied"
/// is correct but a dead end for someone evaluating tinc unprivileged.
fn eacces_hint(path: &std::path::Path, err: &std::io::Error) -> CmdError {
    CmdError::BadInput(format!(
        "Could not access {}: {err}\n  hint: use `-c DIR` for an unprivileged config directory",
        path.display()
    ))
}

fn hint_on_eacces(path: &std::path::Path, e: CmdError) -> CmdError {
    match &e {
        CmdError::Io { err, .. } if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eacces_hint(path, err)
        }
        _ => e,
    }
}

// `makedir` lifted to mod.rs — invite.rs needs it for invitations/ at
// 0700, same chmod-on-exists semantics. Re-exported here for the
// existing call sites; the test below (`makedir_clamps_mode`) stays
// because it tests a behavior `init` relies on, not where the fn lives.
use super::makedir;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::names::PathsInput;
    use std::os::unix::fs::PermissionsExt;

    /// Full happy-path init. Asserts every file exists with the right
    /// content and mode. The mode assertions matter — a 0644 private
    /// key is a security bug, not a cosmetic one.
    #[test]
    fn fresh_init() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(dir.path().join("vpn")),
            ..Default::default()
        });

        run(&paths, "alice").expect("init");

        // tinc.conf: one line.
        let conf = fs::read_to_string(paths.tinc_conf()).unwrap();
        assert_eq!(conf, "Name = alice\n");

        // hosts/alice: one config line, tinc-b64 pubkey.
        let host = fs::read_to_string(paths.host_file("alice")).unwrap();
        let line = host.strip_prefix("Ed25519PublicKey = ").unwrap();
        let b64 = line.strip_suffix('\n').unwrap();
        // 32 bytes → 43 chars in tinc's no-padding b64.
        assert_eq!(b64.len(), 43);
        // It should round-trip through tinc-b64 decode. (Not standard
        // b64 — `b64::decode` is the LSB-first variant.)
        let decoded = tinc_crypto::b64::decode(b64).unwrap();
        assert_eq!(decoded.len(), 32);

        // Private key: PEM, mode 0600. The mode check is the security
        // assertion.
        let priv_path = paths.ed25519_private();
        let priv_mode = fs::metadata(&priv_path).unwrap().permissions().mode();
        assert_eq!(
            priv_mode & 0o777,
            0o600,
            "private key must be 0600, got {priv_mode:o}"
        );
        // It loads via `keypair::read_private`, which goes through the
        // full PEM parser. End-to-end key write→read.
        let sk = keypair::read_private(&priv_path).unwrap();
        // And the public half matches what's in hosts/alice.
        assert_eq!(sk.public_key().as_slice(), decoded.as_slice());

        // tinc-up: executable, has the shebang.
        let up_path = paths.tinc_up();
        let up_mode = fs::metadata(&up_path).unwrap().permissions().mode();
        assert_eq!(
            up_mode & 0o777,
            0o755,
            "tinc-up must be executable, got {up_mode:o}"
        );
        let up = fs::read_to_string(&up_path).unwrap();
        assert!(up.starts_with("#!/bin/sh\n"));
        assert!(up.contains("Unconfigured tinc-up"));

        // Dirs exist.
        assert!(paths.hosts_dir().is_dir());
        assert!(paths.cache_dir().is_dir());
    }

    /// Re-init on an existing confbase fails. The private key is NOT
    /// touched. This is the footgun guard.
    #[test]
    fn reinit_fails() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(dir.path().join("vpn")),
            ..Default::default()
        });

        run(&paths, "alice").expect("first init");
        let key_before = fs::read(paths.ed25519_private()).unwrap();

        let err = run(&paths, "bob").expect_err("second init should fail");
        assert!(matches!(err, CmdError::Exists(_)));

        // Key untouched. If we accidentally regenerated, this would
        // diff (different OS entropy → different key).
        let key_after = fs::read(paths.ed25519_private()).unwrap();
        assert_eq!(key_before, key_after);

        // tinc.conf still says alice, not bob.
        let conf = fs::read_to_string(paths.tinc_conf()).unwrap();
        assert_eq!(conf, "Name = alice\n");
    }

    #[test]
    fn bad_name_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(dir.path().join("vpn")),
            ..Default::default()
        });

        // Path traversal attempt — the security-relevant case.
        let err = run(&paths, "../evil").expect_err("bad name");
        assert!(matches!(err, CmdError::BadInput(_)));

        // Nothing was created — `check_id` runs before any mkdir.
        // (The `try_exists` on tinc.conf runs first, so the *parent*
        // dir needs to be stat-able, but nothing is *written*.)
        assert!(!paths.confbase.exists());
    }

    /// EACCES at the `mkdir(confbase)` step — the path a non-root
    /// `tinc init` actually hits, since `/etc/tinc` usually doesn't
    /// exist yet so `try_exists` succeeds with `false` and only the
    /// mkdir fails. The error must carry the `-c DIR` hint.
    #[test]
    fn eacces_on_mkdir_hints_at_dash_c() {
        // Root bypasses DAC: mkdir under a 0555 parent succeeds, so
        // `expect_err` panics. Same gate as `list_skip_unreadable`.
        if nix::unistd::geteuid().is_root() {
            eprintln!("(skipping eacces_on_mkdir_hints_at_dash_c: running as root)");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        // Read-only parent: mkdir(confbase) will EACCES.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(dir.path().join("vpn")),
            ..Default::default()
        });

        let err = run(&paths, "alice").expect_err("should fail");
        // Restore perms so tempdir cleanup works.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();

        let CmdError::BadInput(msg) = err else {
            panic!("wrong variant: {err:?}")
        };
        assert!(msg.contains("-c DIR"), "missing hint: {msg}");
    }

    /// Existing confbase dir with wrong perms gets chmod'd to 0755.
    /// This is the surprising `makedir` behavior — chmod-on-exists.
    #[test]
    fn makedir_clamps_mode() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");

        // Pre-create with overly permissive mode.
        fs::create_dir(&confbase).unwrap();
        fs::set_permissions(&confbase, fs::Permissions::from_mode(0o777)).unwrap();

        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase.clone()),
            ..Default::default()
        });
        run(&paths, "alice").expect("init");

        let mode = fs::metadata(&confbase).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "confbase clamped to 0755");
    }
}
