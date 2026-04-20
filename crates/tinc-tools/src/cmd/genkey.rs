//! `cmd_generate_ed25519_keys`.
//!
//! Key rotation. Unlike `init`, the private key file *probably already
//! exists* — that's the whole point. We use append mode after running
//! `disable_old_keys` to comment out the previous PEM block. The
//! result is a private key file with N commented-out blocks and one
//! live one at the end. `read_pem` reads the first *uncommented*
//! block, so it just works.
//!
//! ## `disable_old_keys`
//!
//! Read `filename` line-by-line, write `filename.tmp` (preserving the
//! original's `st_mode`), prefix `#` to:
//!
//! - Any line inside a `-----BEGIN ` ... `-----END ` block where the
//!   BEGIN line contains ` ED25519 ` (note: spaces — `MY_ED25519_FOO`
//!   wouldn't match)
//! - Any line `strncasecmp("Ed25519PublicKey", 16) == 0 &&
//!   strchr(" \t=", buf[16])` — a config-line variant of the same key
//!
//! If anything was disabled, `rename(tmpfile, filename)`. Else
//! `unlink(tmpfile)` — file unchanged.
//!
//! The `Ed25519PublicKey` matcher is the **third hand-rolled config
//! line tokenizer** in this codebase (see `cmd/exchange.rs`
//! `is_name_line` for the second; `tinc-conf` is the first). This one
//! is prefix-16 + delimiter-at-16. `Ed25519PublicKeyBackup = ...` is
//! NOT matched (char 16 is `B`, not in `" \t="`). It's narrower than
//! `tinc-conf`'s tokenizer, which is fine — we want to comment out the
//! exact line that the C wrote, not every line `tinc-conf` would
//! recognize.
//!
//! ## What we drop vs upstream
//!
//! - The `what` parameter (RSA vs Ed25519). `DISABLE_LEGACY` is on.
//! - The interactive filename prompt. See `cmd/init.rs`.
//! - Relative-path absolutization. `Paths` always resolves to absolute.
//!
//! ## Mode preservation
//!
//! Upstream preserves source mode (e.g. user-set 0400) to the tmpfile
//! at create. We `set_permissions` after write — the window is a
//! tmpfile we're about to rename or unlink, so the ordering doesn't
//! matter.
//!
//! ## The two output files
//!
//! Same asymmetry as `init`: private PEM at `ed25519_key.priv`, public
//! config line in `hosts/NAME`. `disable_old_keys` runs on both before
//! append. We don't support genkey-before-init; `sptps_keypair`
//! covers that workflow better.
//!
//! ## Append, not excl
//!
//! `init` opens `O_EXCL`; `genkey` opens `O_APPEND` after
//! `disable_old_keys` neutralized old contents. Comment-out + append
//! = rotation history. `tinc fsck` warns on `#-----BEGIN` for the
//! paper trail.

use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use crate::cmd::exchange::get_my_name;
use crate::cmd::{CmdError, io_err};
use crate::keypair;
use crate::names::Paths;

use tinc_crypto::b64;

/// `cmd_generate_ed25519_keys`. We require the name; see module doc.
///
/// # Errors
///
/// `BadInput` if `tinc.conf` has no `Name` (or doesn't exist). `Io`
/// for any filesystem failure. `Exists` is *not* possible — we append,
/// not excl.
pub fn run(paths: &Paths) -> Result<(), CmdError> {
    let name = get_my_name(paths)?;

    let priv_path = paths.ed25519_private();
    let host_path = paths.host_file(&name);

    // ─── disable_old_keys on both files
    // Run both up front, then both writes — "do all the mutating
    // reads before any mutating write" is a clearer flow.
    //
    // `disable_old_keys` is no-op if the file doesn't exist. So
    // genkey-on-fresh-dir (after `mkdir -p hosts/`) works — disable
    // does nothing, append creates.
    disable_old_keys(&priv_path)?;
    disable_old_keys(&host_path)?;

    // ─── Generate
    eprintln!("Generating Ed25519 key pair:");
    let sk = keypair::generate();
    eprintln!("Done.");

    // ─── Append private (PEM). 0600 is create-mode only; rotation
    // keeps whatever `disable_old_keys` preserved.
    super::write_private_key(&priv_path, &sk, super::OpenKind::Append)?;

    // ─── Append public (config line, LSB-first b64)
    {
        let mut f = open_append(&host_path, 0o666)?;
        let pubkey_b64 = b64::encode(sk.public_key());
        writeln!(f, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_path))?;
    }

    Ok(())
}

/// `disable_old_keys`, minus the RSA branch (see module doc).
///
/// Returns `Ok(true)` if any lines were commented out (and thus the
/// file was rewritten via rename), `Ok(false)` if nothing matched
/// (file untouched — tmpfile was unlinked). `Ok(false)` also if the
/// file didn't exist at all.
///
/// The bool isn't used by `genkey::run` (append happens either way).
/// It's for `fsck`, which calls this and warns if it was a no-op.
///
/// # Errors
///
/// `Io` if reading the source, writing the tmpfile, or the final
/// rename fails. The tmpfile is best-effort-unlinked on error.
///
/// Does NOT error on file-not-found — that's `Ok(false)`.
pub fn disable_old_keys(path: &Path) -> Result<bool, CmdError> {
    // Any open failure → `Ok(false)`; the downstream append surfaces
    // the real error.
    let Ok(r) = fs::File::open(path) else {
        return Ok(false);
    };

    #[cfg(unix)]
    let src_perms = r
        .metadata()
        .map(|m| m.permissions())
        .map_err(io_err(path))?;

    let (tmp_guard, w) = super::TmpGuard::open(path, ".tmp")?;
    let tmp_path = tmp_guard.tmp_path().to_path_buf();

    // ─── Copy with #-prefixing
    let mut r = BufReader::new(r);
    let mut w = BufWriter::new(w);
    let mut disabled = false;
    let mut in_block = false;

    // `read_line` keeps the trailing newline → byte-exact round-trip
    // for unmatched lines, including a final no-newline line.
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.read_line(&mut line).map_err(io_err(path))?;
        if n == 0 {
            break; // EOF
        }

        // ` ED25519 ` is space-delimited so `-----BEGIN MYED25519FOO`
        // doesn't match. `!in_block`: a nested BEGIN is treated as
        // block content (garbage-in-garbage-preserved).
        if !in_block && line.starts_with("-----BEGIN ") && line.contains(" ED25519 ") {
            disabled = true;
            in_block = true;
        }

        // `len >= 17`: 16-byte prefix + at least the delimiter byte.
        let pubkey_line = line.len() >= 17
            && line.as_bytes()[..16].eq_ignore_ascii_case(b"Ed25519PublicKey")
            && matches!(line.as_bytes()[16], b' ' | b'\t' | b'=');
        if pubkey_line {
            disabled = true;
        }

        if in_block || pubkey_line {
            w.write_all(b"#").map_err(io_err(&tmp_path))?;
        }
        w.write_all(line.as_bytes()).map_err(io_err(&tmp_path))?;

        // After the write so the END line itself is `#`-prefixed.
        if in_block && line.starts_with("-----END ") {
            in_block = false;
        }
    }

    // Flush before the perms/rename — `BufWriter::drop` flushes but
    // swallows errors. Explicit flush surfaces ENOSPC etc.
    w.flush().map_err(io_err(&tmp_path))?;
    drop(w); // close the fd before rename — not required on Unix, but clean

    // ─── If nothing was disabled, leave the original alone
    // We wrote a perfect copy, but renaming it over the original is
    // a no-op modulo inode/mtime — avoid the mtime bump.
    if !disabled {
        // Guard's drop unlinks. Explicit drop here is redundant (it'd
        // happen at scope end) but makes the intent visible.
        drop(tmp_guard);
        return Ok(false);
    }

    // ─── Preserve mode, then atomic rename
    // See module doc "Mode preservation" for why we do this here
    // instead of at create.
    #[cfg(unix)]
    fs::set_permissions(&tmp_path, src_perms).map_err(io_err(&tmp_path))?;

    tmp_guard.commit()?;

    Ok(true)
}

/// `O_WRONLY | O_CREAT | O_APPEND`.
///
/// The mode is the *create* mode — only matters if the file doesn't
/// exist. If it does (the rotation case), existing perms win.
///
/// Intentional deviation from upstream: if you `chmod 0400` your
/// private key (read-only), genkey shouldn't silently flip it back
/// to 0600. Upstream does flip it (arguably a bug — undoes your
/// hardening); ours respects it.
fn open_append(path: &Path, mode: u32) -> Result<fs::File, CmdError> {
    super::open_nofollow(path, super::OpenKind::Append, mode)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Nonexistent file → `Ok(false)`, no tmpfile left behind.
    #[test]
    fn disable_nonexistent() {
        let dir = tmp();
        let path = dir.path().join("nope");
        assert!(!disable_old_keys(&path).unwrap());
        assert!(!path.exists());
        assert!(!dir.path().join("nope.tmp").exists());
    }

    /// File with no matching lines → `Ok(false)`, file untouched.
    /// (No mtime bump — we check by content not mtime, but the
    /// guarantee is "tmpfile unlinked, original unrenamed".)
    #[test]
    fn disable_no_match() {
        let dir = tmp();
        let path = dir.path().join("f");
        let content = "Subnet = 10.0.0.0/24\nAddress = 1.2.3.4\n";
        fs::write(&path, content).unwrap();
        assert!(!disable_old_keys(&path).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        // Tmpfile gone.
        assert!(!dir.path().join("f.tmp").exists());
    }

    /// Single config line → `#` prepended, rest preserved.
    #[test]
    fn disable_config_line() {
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(
            &path,
            "Subnet = 10.0.0.0/24\nEd25519PublicKey = abc123\nAddress = 1.2.3.4\n",
        )
        .unwrap();
        assert!(disable_old_keys(&path).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "Subnet = 10.0.0.0/24\n#Ed25519PublicKey = abc123\nAddress = 1.2.3.4\n"
        );
    }

    /// PEM block → every line `#`-prefixed, including BEGIN and END.
    #[test]
    fn disable_pem_block() {
        let dir = tmp();
        let path = dir.path().join("f");
        // Real-ish PEM. The body is two lines.
        fs::write(
            &path,
            "-----BEGIN ED25519 PRIVATE KEY-----\nbody1\nbody2\n-----END ED25519 PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(disable_old_keys(&path).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "#-----BEGIN ED25519 PRIVATE KEY-----\n#body1\n#body2\n#-----END ED25519 PRIVATE KEY-----\n"
        );
    }

    /// PEM block with surrounding config lines. Only the block gets `#`.
    /// This is the actual layout of a private key file after one prior
    /// genkey: comment, PEM, then a new PEM was appended.
    #[test]
    fn disable_pem_block_surrounded() {
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(
            &path,
            "# old key from 2024\n-----BEGIN ED25519 PRIVATE KEY-----\nbody\n-----END ED25519 PRIVATE KEY-----\n# end\n",
        )
        .unwrap();
        assert!(disable_old_keys(&path).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# old key from 2024\n#-----BEGIN ED25519 PRIVATE KEY-----\n#body\n#-----END ED25519 PRIVATE KEY-----\n# end\n"
        );
    }

    /// `Ed25519PublicKeyBackup` is NOT matched (char 16 is `B`).
    /// This is the prefix-16+delim-at-16 specificity — see module doc.
    #[test]
    fn disable_config_line_exact_len() {
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(&path, "Ed25519PublicKeyBackup = abc\n").unwrap();
        assert!(!disable_old_keys(&path).unwrap());
        // Unchanged.
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "Ed25519PublicKeyBackup = abc\n"
        );
    }

    /// Tab and `=` (no space) are valid delimiters at char 16.
    #[test]
    fn disable_config_line_delims() {
        for (delim, want) in [
            ("Ed25519PublicKey = x\n", true),   // space
            ("Ed25519PublicKey\t= x\n", true),  // tab
            ("Ed25519PublicKey=x\n", true),     // = directly
            ("Ed25519PublicKey\n", false),      // newline at 16: not in " \t="
            ("Ed25519PublicKeys = x\n", false), // 's' at 16
        ] {
            let dir = tmp();
            let path = dir.path().join("f");
            fs::write(&path, delim).unwrap();
            assert_eq!(disable_old_keys(&path).unwrap(), want, "input: {delim:?}");
        }
    }

    /// Case-insensitive on the key name.
    #[test]
    fn disable_config_line_case() {
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(&path, "ed25519publickey = abc\n").unwrap();
        assert!(disable_old_keys(&path).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "#ed25519publickey = abc\n"
        );
    }

    /// `-----BEGIN RSA PRIVATE KEY-----` is NOT matched.
    /// We dropped the RSA branch entirely.
    #[test]
    fn disable_ignores_rsa() {
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(
            &path,
            "-----BEGIN RSA PRIVATE KEY-----\nbody\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(!disable_old_keys(&path).unwrap());
    }

    /// `-----BEGIN MYED25519FOO-----` (no space before ED25519) NOT
    /// matched. ` ED25519 ` is space-delimited.
    #[test]
    fn disable_space_delimited_type() {
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(
            &path,
            "-----BEGIN MYED25519FOO-----\nbody\n-----END MYED25519FOO-----\n",
        )
        .unwrap();
        assert!(!disable_old_keys(&path).unwrap());
    }

    /// END check doesn't validate type. `-----END WHATEVER-----` ends
    /// an ED25519 block. Garbage-in-garbage-preserved.
    #[test]
    fn disable_end_type_unchecked() {
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(
            &path,
            "-----BEGIN ED25519 PRIVATE KEY-----\nbody\n-----END WHATEVER-----\nafter\n",
        )
        .unwrap();
        assert!(disable_old_keys(&path).unwrap());
        // `after` is NOT prefixed — block ended at the (mismatched) END.
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "#-----BEGIN ED25519 PRIVATE KEY-----\n#body\n#-----END WHATEVER-----\nafter\n"
        );
    }

    /// Mode preservation: `chmod 0400`, disable, check it's still 0400.
    /// Unix-only.
    #[cfg(unix)]
    #[test]
    fn disable_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp();
        let path = dir.path().join("f");
        fs::write(&path, "Ed25519PublicKey = x\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(disable_old_keys(&path).unwrap());
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
    }

    /// No trailing newline on the last line: preserved.
    /// `read_line` returns the partial line, then 0. Round-trip.
    #[test]
    fn disable_no_trailing_newline() {
        let dir = tmp();
        let path = dir.path().join("f");
        // Note: no \n after `abc`.
        fs::write(&path, "Ed25519PublicKey = abc").unwrap();
        assert!(disable_old_keys(&path).unwrap());
        // # prepended, no \n added.
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "#Ed25519PublicKey = abc"
        );
    }

    /// **The full rotation workflow.** This is what `genkey::run` does
    /// to the private key file: `disable_old_keys`, then append a fresh
    /// PEM. The result has one commented block and one live one.
    /// `tinc-conf::pem::read_pem` reads the live one (it skips
    /// `#`-comments — they're not `-----BEGIN`).
    #[test]
    fn rotation_roundtrip() {
        use tinc_conf::pem::read_pem;
        let dir = tmp();
        let path = dir.path().join("ed25519_key.priv");

        // Round 1: genkey on empty (init-equivalent).
        let sk1 = keypair::generate();
        {
            disable_old_keys(&path).unwrap(); // no-op (file doesn't exist)
            crate::cmd::write_private_key(&path, &sk1, crate::cmd::OpenKind::Append).unwrap();
        }
        // File has one PEM block.
        let blob1 = read_pem(fs::File::open(&path).unwrap(), keypair::TY_PRIVATE, 96).unwrap();
        assert_eq!(&blob1[..], &sk1.to_blob()[..]);

        // Round 2: rotate.
        let sk2 = keypair::generate();
        {
            assert!(disable_old_keys(&path).unwrap()); // sk1's block disabled
            crate::cmd::write_private_key(&path, &sk2, crate::cmd::OpenKind::Append).unwrap();
        }

        // File now has #-block then live block. read_pem gets the live one.
        let blob2 = read_pem(fs::File::open(&path).unwrap(), keypair::TY_PRIVATE, 96).unwrap();
        assert_eq!(&blob2[..], &sk2.to_blob()[..]);
        // And it's NOT sk1. (Non-astronomical chance of collision.)
        assert_ne!(&blob2[..], &blob1[..]);

        // The file shape: one #-block, one live block.
        let content = fs::read_to_string(&path).unwrap();
        let begins = content.matches("-----BEGIN ").count();
        let hashed = content.matches("#-----BEGIN ").count();
        assert_eq!(begins, 2); // both blocks have BEGIN (the # is before)
        assert_eq!(hashed, 1); // one is commented
    }
}
