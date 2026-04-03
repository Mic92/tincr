//! `tinc init NAME`. C reference: `tincctl.c:2209-2301` `cmd_init`.
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
//! ## Intentional behavioral changes from C
//!
//! These are documented in `RUST_REWRITE_PLAN.md` Phase 4a as deliberate
//! deviations, not bugs to fix later.
//!
//! ### No interactive name prompt
//!
//! C `cmd_init` prompts on stdin if `argc < 2 && isatty(stdin)`.
//! We don't. Rationale:
//!
//! 1. The prompt is the **only** interactive thing in `tinc init`.
//!    Everything else is non-interactive. Adding a tty check + readline
//!    + the strip-newline dance is ~30 lines for one prompt.
//! 2. Scripts call `tinc init NAME` directly. Nobody types `tinc init`
//!    bare and waits for a prompt. The C path exists because the
//!    interactive `tinc> ` shell mode reuses `cmd_init`, and *there*
//!    the prompt makes sense. We don't have shell mode yet (5b).
//! 3. "Required positional argument" is a clearer contract than
//!    "required positional argument unless you're a tty".
//!
//! When/if we add shell mode in 5b, the prompt comes back as a
//! shell-layer concern: shell prompts → calls `init::run("alice")`.
//! The command itself stays prompt-free.
//!
//! ### No `check_port`
//!
//! C tries to bind 655; if busy, picks a random high port and writes
//! `Port = N` to the host file. Best-effort QoL — init succeeds
//! regardless. Dropped for now because (a) it pulls in socket code we
//! don't otherwise need in this command, (b) the random-port pick is
//! often *wrong* (your firewall doesn't allow it; your NAT doesn't
//! forward it). Better to fail loudly at first daemon start ("could
//! not bind to 655: address in use") than silently pick port 7423 the
//! user doesn't know about. Can revisit.
//!
//! ### No RSA keygen
//!
//! `DISABLE_LEGACY` is permanently on. We don't speak the 1.0.x RSA
//! protocol; we don't generate RSA keys. C wraps it in `#ifndef
//! DISABLE_LEGACY` (`tincctl.c:2269`); ours is just absent.
//!
//! ## File mode subtlety
//!
//! `fopenmask` in C does a umask dance: read current umask, set umask
//! to `~perms & 0777`, fopen (creates with `0666 & ~umask`), then
//! `fchmod` to `perms` if any read bit is set, restore umask. The
//! point of this elaborate dance:
//!
//! - Private key (0600): even if umask is 0002 (group-write), the key
//!   stays 0600. **Security**: don't let a permissive umask leak the
//!   key to group-readable.
//! - tinc-up (0777 → 0755 after umask 022): the executable bit
//!   survives. `fopen("w")` would give 0644 — `fchmod` is what makes
//!   it executable.
//!
//! We don't replicate the dance. We use `OpenOptions::mode()` (sets
//! the create-mode directly, kernel applies umask) plus an explicit
//! `set_permissions` for executables. Simpler, same outcome:
//!
//! - Private key: `mode(0o600)`, kernel umask doesn't widen it (umask
//!   only *clears* bits). Same security guarantee.
//! - tinc-up: `set_permissions(0o755)` after write. Same +x outcome.
//!
//! What we *lose*: if the user's umask is **more** restrictive than
//! 022 (say 077), the C `fopenmask` would honor it (key becomes 0600
//! either way, but tinc-up becomes 0700 instead of 0755). Our
//! `set_permissions(0o755)` ignores umask. This is fine — a user with
//! umask 077 who wants their tinc-up group-unreadable can `chmod`. The
//! security-relevant file (the key) is unaffected.
//!
//! ## Idempotency: NO
//!
//! `tinc init` on an existing confbase **fails** (`tinc.conf already
//! exists`). C: `if(!access(tinc_conf, F_OK)) { fprintf; return 1; }`.
//! This is correct — re-init would overwrite the private key, which is
//! a footgun. You want a fresh net? `rm -rf /etc/tinc/NAME` first,
//! deliberately.
//!
//! Partial-state-on-error: if `mkdir hosts/` succeeds and key writing
//! fails, you get a half-created confbase. C does the same (no
//! cleanup, no rollback). The next `tinc init` will fail because
//! `tinc.conf` was written. The user has to `rm` and retry. Not great,
//! but matches upstream and the failure mode is rare (disk full, perm
//! flip mid-init).

use std::fs::{self, OpenOptions};
use std::io::Write;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::cmd::{CmdError, io_err};
use crate::keypair;
use crate::names::{Paths, check_id};

use tinc_conf::pem::write_pem;
use tinc_crypto::b64;

/// PEM type for the private key. Same constant as `keypair.rs`; not
/// re-exported because the host-file path here doesn't write a public
/// PEM at all (it writes a config line instead).
const TY_PRIVATE: &str = "ED25519 PRIVATE KEY";

/// `cmd_init`. Takes the resolved `Paths` and the node name from argv.
///
/// Progress goes to stderr (matches C `fprintf(stderr, ...)`). Not
/// stdout — stdout is reserved for command *output* (export does this),
/// progress chatter is diagnostics.
///
/// # Errors
///
/// `Exists` if `tinc.conf` already exists. `BadInput` if the name fails
/// `check_id`. `Io` for any filesystem failure (mkdir, open, write,
/// chmod) — the path tells you which.
///
/// Doesn't roll back on partial failure. See module doc.
#[allow(clippy::too_many_lines)] // it's a recipe — N steps in sequence,
// breaking it up just hides the order
pub fn run(paths: &Paths, name: &str) -> Result<(), CmdError> {
    // ─── Guard: already initialized?
    // C: `if(!access(tinc_conf, F_OK))` — `access(F_OK)` is "exists?",
    // returns 0 (success) if it does. The `!` flips it. We use
    // `try_exists` not `exists` because `exists` swallows EACCES
    // (returns false on permission-denied to the parent dir), and
    // we'd rather surface that as `Io` than silently re-init.
    let tinc_conf = paths.tinc_conf();
    match tinc_conf.try_exists() {
        Ok(true) => return Err(CmdError::Exists(tinc_conf)),
        Ok(false) => {}
        Err(e) => return Err(io_err(&tinc_conf)(e)),
    }

    // ─── Guard: valid node name?
    // C: `if(!check_id(name))`. Doing this *after* the exists check
    // matches the C order (`tincctl.c:2249` is after `:2210`). Both
    // are pure checks so order is academic, but fidelity is free.
    if !check_id(name) {
        return Err(CmdError::BadInput(
            "Invalid Name! Only a-z, A-Z, 0-9 and _ are allowed.".into(),
        ));
    }

    // ─── makedirs(DIR_HOSTS | DIR_CONFBASE | DIR_CONFDIR | DIR_CACHE)
    // C `fs.c:23-64`. The order matters: confdir before confbase
    // (parent before child), confbase before hosts/cache (children).
    // C `makedir` does `mkdir; if EEXIST chmod` — i.e. it forces the
    // mode even if the dir was already there. We do the same: an
    // existing `/etc/tinc/myvpn` with mode 0777 gets clamped to 0755.
    // Paranoia, but cheap.
    //
    // `confdir` is `Some` iff `-c` wasn't given. See `Paths::confdir` doc.
    if let Some(confdir) = &paths.confdir {
        makedir(confdir, 0o755)?;
    }
    makedir(&paths.confbase, 0o755)?;
    makedir(&paths.hosts_dir(), 0o755)?;
    makedir(&paths.cache_dir(), 0o755)?;

    // ─── Write tinc.conf
    // C: `fprintf(f, "Name = %s\n", name)`. That's the entire file.
    // Mode is whatever `fopen("w")` gives — 0666 & ~umask, typically
    // 0644. We use `File::create` (same semantics).
    //
    // No `O_EXCL` — we already checked `try_exists` above. There's a
    // TOCTOU here (check, then someone-else-creates, then we
    // overwrite), but the C has the same race and the threat model
    // doesn't include hostile concurrent `tinc init`s.
    {
        let mut f = fs::File::create(&tinc_conf).map_err(io_err(&tinc_conf))?;
        writeln!(f, "Name = {name}").map_err(io_err(&tinc_conf))?;
    }

    // ─── Generate Ed25519 keypair
    // C `ed25519_keygen(false)`: generate, write private as PEM to
    // `ed25519_key.priv` (mode 0600), write public as a config *line*
    // to `hosts/NAME` (NOT a PEM file — `Ed25519PublicKey = <b64>`).
    //
    // The asymmetry matters. The private key file is read by the
    // daemon at startup (`net_setup.c` `read_ecdsa_private_key`) via
    // `read_pem`. The public key in `hosts/NAME` is read by *peers*
    // via the config parser (`get_config_string("Ed25519PublicKey")`).
    // Different readers, different formats. `keypair::write_pair` does
    // PEM-both-sides for `sptps_keypair`; this does PEM-then-config.
    eprintln!("Generating Ed25519 key pair:");
    let sk = keypair::generate();
    eprintln!("Done.");

    // Private: PEM, mode 0600. `O_EXCL` here because clobbering an
    // existing key is *catastrophic* — you lose the ability to prove
    // identity to existing peers. C uses mode "a" (append) which has a
    // similar effect (won't truncate), combined with `disable_old_keys`
    // commenting out prior blocks. For init, the file shouldn't exist
    // at all (we just made the dir); excl is the right semantics.
    {
        let priv_path = paths.ed25519_private();
        let f = open_mode_excl(&priv_path, 0o600)?;
        let mut w = std::io::BufWriter::new(f);
        // 96-byte blob, same as `keypair::write_pair`.
        write_pem(&mut w, TY_PRIVATE, &sk.to_blob()).map_err(io_err(&priv_path))?;
        w.flush().map_err(io_err(&priv_path))?;
    }

    // Public: config line in `hosts/NAME`. C: `fprintf(f,
    // "Ed25519PublicKey = %s\n", b64encode_tinc(public, ..., 32))`.
    // The b64 is tinc's LSB-first variant — `b64::encode`, NOT
    // standard base64. A peer's `ecdsa_set_base64_public_key`
    // (`ecdsa.c:43`) decodes with `b64decode_tinc`; standard b64 here
    // would fail to round-trip and the peer rejects your key. This
    // is the highest-stakes line in the whole file.
    //
    // Mode is 0666 in C (`ask_and_open(..., 0666)`); after umask 022
    // that's 0644. The host file is meant to be shared (export sends
    // it to peers), so world-readable is fine. We use `OpenOptions`
    // with append — `cmd_init` is the first writer but `check_port`
    // (when we add it) appends `Port = N` to the same file.
    {
        let host_path = paths.host_file(name);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&host_path)
            .map_err(io_err(&host_path))?;
        let pubkey_b64 = b64::encode(sk.public_key());
        writeln!(f, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_path))?;
    }

    // ─── tinc-up stub
    // Unix-only (C: `#ifndef HAVE_WINDOWS`). A shell script that yells
    // at you to configure it. Mode 0777 in C, becomes 0755 after umask.
    //
    // The C checks `if(access(filename, F_OK))` — only write if it
    // *doesn't* exist (note: `access` returns 0 on exists, so the
    // condition is "doesn't exist"). We just made the directory, so
    // it can't exist, but the check matters if `cmd_init` is ever
    // called on a partial-state confbase (it shouldn't be —
    // `tinc.conf` exists check should catch that — but defense in
    // depth). `O_EXCL` gives us the same don't-clobber.
    #[cfg(unix)]
    {
        let up_path = paths.tinc_up();
        // `try_exists` then `O_EXCL` is belt-and-suspenders, but it
        // lets us silently skip (matching C) instead of erroring on
        // EEXIST. The C silently skips; so do we.
        if !up_path.try_exists().map_err(io_err(&up_path))? {
            let f = open_mode_excl(&up_path, 0o755)?;
            // The text matches `tincctl.c:2294` — including the
            // commented-out ifconfig line. That line is a fossil
            // (modern Linux uses `ip addr add`, not `ifconfig`), but
            // changing it is a separate decision. Fidelity.
            let mut w = std::io::BufWriter::new(f);
            // Literal newlines in the source make the multi-line
            // string read like the file it produces. The C uses one
            // long `\n\n` string; same content.
            w.write_all(
                b"#!/bin/sh\n\
                  \n\
                  echo 'Unconfigured tinc-up script, please edit '$0'!'\n\
                  \n\
                  #ifconfig $INTERFACE <your vpn IP address> netmask <netmask of whole VPN>\n",
            )
            .map_err(io_err(&up_path))?;
            w.flush().map_err(io_err(&up_path))?;
            // The +x bit: `OpenOptions::mode(0o755)` sets the create
            // mode, but the kernel applies umask, so umask 022 gives
            // 0755 (good) but umask 077 gives 0700. C `fopenmask` does
            // an explicit `fchmod` to make sure +x sticks regardless.
            // We do the same. `set_permissions` is `chmod`, not
            // `fchmod` — we already closed the file (BufWriter drop),
            // path-based is fine.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&up_path, fs::Permissions::from_mode(0o755))
                    .map_err(io_err(&up_path))?;
            }
        }
    }

    Ok(())
}

// `makedir` lifted to mod.rs — invite.rs needs it for invitations/ at
// 0700, same chmod-on-exists semantics. Re-exported here for the
// existing call sites; the test below (`makedir_clamps_mode`) stays
// because it tests a behavior `init` relies on, not where the fn lives.
use super::makedir;

/// Open for write, create with explicit mode, fail if exists.
///
/// `O_WRONLY | O_CREAT | O_EXCL | O_TRUNC` (trunc is moot with excl,
/// but harmless). The mode is the *create* mode — kernel still applies
/// umask, so `mode=0o600` with umask 022 gives 0600 (umask only
/// clears bits, never sets). For files where we want bits *above* what
/// umask allows (executables), the caller does a follow-up `chmod`.
///
/// Why `O_EXCL` instead of C's `fopenmask("a", ...)` append mode: for
/// the private key, append-to-existing is just as bad as truncate
/// (`disable_old_keys` makes append work in C by commenting out old
/// blocks first; we don't have that yet, and excl is the right
/// semantics for init anyway — see callers).
fn open_mode_excl(path: &std::path::Path, mode: u32) -> Result<fs::File, CmdError> {
    #[cfg(unix)]
    let opts = {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true).mode(mode);
        o
    };
    #[cfg(not(unix))]
    let opts = {
        let _ = mode;
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        o
    };
    opts.open(path).map_err(io_err(path))
}

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
        // Well, almost: the `try_exists` check on tinc.conf runs
        // first (matching C order), so the *parent* dir needs to be
        // stat-able, but nothing is *written*. Confirm: confbase
        // doesn't exist.
        assert!(!paths.confbase.exists());
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
