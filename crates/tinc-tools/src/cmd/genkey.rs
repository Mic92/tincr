//! `cmd_generate_ed25519_keys` — `tincctl.c:2351`.
//!
//! Key rotation. Unlike `init`, the private key file *probably already
//! exists* — that's the whole point. The C uses append mode (`"a"`)
//! after running `disable_old_keys` to comment out the previous PEM
//! block. The result is a private key file with N commented-out blocks
//! and one live one at the end. `read_pem` reads the first
//! *uncommented* block, so it just works.
//!
//! ## `disable_old_keys` (`keys.c:10-100`)
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
//! ## What we drop vs C
//!
//! - The `what` parameter. C does `strstr(what, "Ed25519")` to decide
//!   whether to look for ED25519 vs RSA blocks. We never disable RSA
//!   (`DISABLE_LEGACY` is permanently on). One key type, no parameter.
//! - The interactive filename prompt (`ask_and_open`'s `ask` half).
//!   Same deviation as `init` — see `cmd/init.rs` module doc.
//! - The relative-path absolutization. `ask_and_open` does `getcwd` +
//!   join if the path doesn't start with `/`. Ours always does
//!   (`Paths` resolves to absolute), so it's dead code.
//! - The `fopenmask` umask dance. C does `umask(0); umask(~perms);
//!   fopen; umask(old)` — three syscalls to make `fopen` use a
//!   specific mode without `O_CREAT`-style explicit perms. We have
//!   `OpenOptions::mode()`. The dance is a workaround for `fopen`
//!   not exposing `open(2)`'s third argument; we don't have `fopen`.
//!
//! ## Mode preservation
//!
//! C does `fstat(fileno(r), &st)` then `fopenmask(tmpfile, "w",
//! st.st_mode)`. The point: if the user `chmod 0400` their private
//! key (read-only, even owner can't write — paranoid but legal), the
//! tmpfile should also be 0400. We preserve via `Metadata::permissions`
//! on the source → `set_permissions` on the destination after write.
//! Slight ordering difference (C sets at create, we set after write)
//! but the window is the tmpfile, which we're about to rename or
//! unlink. Doesn't matter.
//!
//! ## The two output files
//!
//! Same asymmetry as `init` (see `cmd/init.rs`): private key is PEM
//! at `ed25519_key.priv`, public key is a config line in `hosts/NAME`.
//! Genkey runs `disable_old_keys` on *both* before append: the private
//! key file gets `#-----BEGIN ED25519 PRIVATE KEY-----` etc., the host
//! file gets `#Ed25519PublicKey = oldb64`.
//!
//! C edge: if `name` is unknown (no `tinc.conf` or it has no `Name`),
//! the public key goes to `ed25519_key.pub` as a *PEM file* (not a
//! config line). This is `cmd_generate_ed25519_keys` running before
//! `init` — unusual (why generate keys for a node that has no
//! identity?), but the C supports it (`tincctl.c:386-390`). We don't.
//! `get_my_name` errors on no-conf and we propagate. The only
//! workflow that hits this is "I want to inspect a keypair before
//! committing to a name", and `sptps_keypair` already does that
//! better (it writes a PEM *pair*).
//!
//! ## Append, not excl
//!
//! `init` opens `O_EXCL` — clobbering an existing key is catastrophic.
//! `genkey` opens `O_APPEND` — the file is *expected* to exist, and
//! `disable_old_keys` already neutralized the old contents. This is
//! the load-bearing pairing: comment-out + append = rotation history.
//! `tinc fsck` reads the same file and warns on `#-----BEGIN`, so
//! you have a paper trail.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::cmd::exchange::get_my_name;
use crate::cmd::{CmdError, io_err};
use crate::keypair;
use crate::names::Paths;

use tinc_conf::pem::write_pem;
use tinc_crypto::b64;

/// Same constant as `init.rs`. Not factored into `mod.rs` because it's
/// the *PEM type string*, not a `cmd/` concept — if it lives anywhere
/// shared it's `keypair.rs`, but that already has it as `TY_PRIVATE`
/// and re-exporting two-word constants is more noise than help.
const TY_PRIVATE: &str = "ED25519 PRIVATE KEY";

/// `cmd_generate_ed25519_keys`. The 5-line wrapper in C
/// (`tincctl.c:2351`) is `name = get_my_name(false)` (no error if
/// missing — `false` is `verbose`, not `required`) then
/// `ed25519_keygen(true)`. We require the name; see module doc.
///
/// # Errors
///
/// `BadInput` if `tinc.conf` has no `Name` (or doesn't exist). `Io`
/// for any filesystem failure. `Exists` is *not* possible — we append,
/// not excl.
pub fn run(paths: &Paths) -> Result<(), CmdError> {
    // ─── Get our name ───────────────────────────────────────────────
    // C `tincctl.c:2360`: `if(!name) name = get_my_name(false)`. The
    // `false` means don't print an error if missing — C falls through
    // to writing `ed25519_key.pub` as a PEM file in that case
    // (`tincctl.c:389`). We don't support that; see module doc.
    //
    // `get_my_name` already errors on no-conf with a `BadInput`
    // pointing at `tinc.conf` (see `cmd/exchange.rs:118`). Perfect.
    let name = get_my_name(paths)?;

    let priv_path = paths.ed25519_private();
    let host_path = paths.host_file(&name);

    // ─── disable_old_keys on both files ─────────────────────────────
    // C `tincctl.c:338` runs it via `ask_and_open` for each of the two
    // opens. We run both up front, then both writes. Same effect (each
    // disable+write pair is independent of the other), and "do all the
    // mutating reads before any mutating write" is a clearer flow.
    //
    // `disable_old_keys` is no-op if the file doesn't exist (returns
    // `Ok(false)`). C: `if(!r) return false`. So genkey-on-fresh-dir
    // (after `mkdir -p hosts/`) works — disable does nothing, append
    // creates.
    disable_old_keys(&priv_path)?;
    disable_old_keys(&host_path)?;

    // ─── Generate ───────────────────────────────────────────────────
    // Same progress chatter as `init`. C `tincctl.c:362-370`.
    eprintln!("Generating Ed25519 key pair:");
    let sk = keypair::generate();
    eprintln!("Done.");

    // ─── Append private (PEM) ───────────────────────────────────────
    // C: `ask_and_open(fname, "...", "a", ask, 0600)`. Mode `"a"` is
    // `O_WRONLY | O_CREAT | O_APPEND`. The 0600 is the *create* mode;
    // if the file exists (the rotation case), the existing mode wins,
    // and `disable_old_keys` already preserved it on the tmpfile that
    // got renamed in. So mode here only matters for the first-ever
    // genkey on a path.
    {
        let f = open_append(&priv_path, 0o600)?;
        let mut w = BufWriter::new(f);
        write_pem(&mut w, TY_PRIVATE, &sk.to_blob()).map_err(io_err(&priv_path))?;
        w.flush().map_err(io_err(&priv_path))?;
    }

    // ─── Append public (config line) ────────────────────────────────
    // C: `ask_and_open(..., 0666)` then `fprintf(f, "Ed25519PublicKey
    // = %s\n", ...)`. Same LSB-first b64 as init. Same
    // highest-stakes-line caveat.
    {
        let mut f = open_append(&host_path, 0o666)?;
        let pubkey_b64 = b64::encode(sk.public_key());
        writeln!(f, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_path))?;
    }

    Ok(())
}

/// `keys.c:10` `disable_old_keys`, minus the RSA branch and the `what`
/// parameter (see module doc).
///
/// Returns `Ok(true)` if any lines were commented out (and thus the
/// file was rewritten via rename), `Ok(false)` if nothing matched (and
/// the file is untouched — tmpfile was unlinked). `Ok(false)` also if
/// the file didn't exist at all.
///
/// The bool isn't used by `genkey::run` (it doesn't care — append
/// happens either way). It's for `fsck`, which calls this and then
/// warns if it was a no-op (`fsck.c:274` checks the return).
///
/// # Errors
///
/// `Io` if reading the source, writing the tmpfile, or the final
/// rename fails. The tmpfile is best-effort-unlinked on error (C does
/// the same: `keys.c:76` `unlink(tmpfile)` in the error path).
///
/// Does NOT error on file-not-found — that's `Ok(false)`.
pub fn disable_old_keys(path: &Path) -> Result<bool, CmdError> {
    // ─── Open source ────────────────────────────────────────────────
    // C: `FILE *r = fopen(filename, "r"); if(!r) return false;`
    // ENOENT is silent-false. EACCES is also silent-false in C (it
    // doesn't check errno). We follow: any open failure on the source
    // is `Ok(false)`. The downstream append will surface the real
    // error (can't append to a file you can't read either, usually).
    let Ok(r) = fs::File::open(path) else {
        return Ok(false);
    };

    // ─── Preserve mode ──────────────────────────────────────────────
    // C: `struct stat st = {.st_mode = 0600}; fstat(fileno(r), &st);`
    // The `= 0600` initializer is the fallback if fstat fails (which
    // it won't on a just-opened fd, but defensiveness). We `metadata()`
    // on the open file (== fstat) and capture perms.
    //
    // We apply this *after* writing, not at create. C applies at create
    // via `fopenmask`. The window is the tmpfile, which we're about to
    // rename or unlink — observable difference is zero unless someone
    // is racing us on `<path>.tmp`, and the C has the same race on the
    // umask-restore in `fopenmask`.
    #[cfg(unix)]
    let src_perms = r
        .metadata()
        .map(|m| m.permissions())
        .map_err(io_err(path))?;

    // ─── Open tmpfile ───────────────────────────────────────────────
    // C: `snprintf(tmpfile, ..., "%s.tmp", filename)`. Just `.tmp`
    // suffix, no mkstemp randomness. There's a race here (concurrent
    // `disable_old_keys` on the same path stomp each other's tmpfile)
    // but the C has it too and the threat model doesn't include that.
    //
    // `add_extension` doesn't exist; manual OsString concat. Not
    // `with_extension` — that *replaces* the existing extension.
    // `ed25519_key.priv` would become `ed25519_key.tmp`, which
    // collides with `ed25519_key.pub.tmp` → ... no it doesn't, those
    // are different paths. But `foo.tar.gz` → `foo.tar.tmp` is wrong
    // semantics. Append-suffix is what C does; do that.
    let tmp_path = {
        let mut s = path.as_os_str().to_owned();
        s.push(".tmp");
        std::path::PathBuf::from(s)
    };

    // C `fopenmask(tmpfile, "w", st.st_mode)`. We create + truncate.
    // No `O_EXCL` — C overwrites a stale tmpfile, so do we. (A stale
    // tmpfile means a previous run was interrupted; clobbering it is
    // the right recovery.)
    let w = fs::File::create(&tmp_path).map_err(io_err(&tmp_path))?;

    // RAII guard: unlink tmpfile if we bail. Disarmed on the success
    // path right before rename. C does this manually with `if(w)
    // unlink(tmpfile)` in each error branch; we do it once.
    let mut tmp_guard = TmpGuard(Some(tmp_path.clone()));

    // ─── Copy with #-prefixing ──────────────────────────────────────
    let mut r = BufReader::new(r);
    let mut w = BufWriter::new(w);
    let mut disabled = false;
    let mut in_block = false;

    // C uses `fgets(buf, sizeof(buf), r)` — keeps the trailing
    // newline. `BufRead::lines()` strips it. We need to preserve
    // newlines (the file should round-trip byte-exact for unmatched
    // lines), so we use `read_line` which keeps them.
    //
    // `read_line` also handles a final line with no trailing newline
    // correctly (returns it without `\n`, then next call returns 0).
    // C `fgets` does the same. The output then also has no trailing
    // newline. Round-trip preserved.
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.read_line(&mut line).map_err(io_err(path))?;
        if n == 0 {
            break; // EOF
        }

        // The matching is on the line *with* its trailing newline.
        // `strncmp(buf, "-----BEGIN ", 11)` doesn't care about it
        // (the prefix is short). `strchr(" \t=", buf[16])` — char 16
        // is past the newline only on a 16-char line, which
        // "Ed25519PublicKey" exactly is, but then there's no `=`
        // after it so the match should fail anyway. Edge: a line
        // that is *exactly* `Ed25519PublicKey\n` (17 bytes) has
        // `buf[16] = '\n'`, and `'\n'` is not in `" \t="`. Correct.
        // A line `Ed25519PublicKey=x\n` has `buf[16] = '='`. Match.

        // ─── PEM block detection ────────────────────────────────────
        // C `keys.c:33`: `if(!block && !strncmp(buf, "-----BEGIN ", 11))`
        // The `!block` means a BEGIN inside a block is ignored (treated
        // as block content). Shouldn't happen in well-formed PEM but
        // garbage-in-garbage-preserved.
        //
        // C then does `strstr(buf, " ED25519 ")` — space-delimited
        // substring anywhere in the line. `-----BEGIN ED25519 PRIVATE
        // KEY-----` has it; `-----BEGIN MYED25519FOO-----` doesn't
        // (no space before ED25519). We dropped the `strstr(what,
        // "Ed25519")` check — see module doc.
        if !in_block && line.starts_with("-----BEGIN ") && line.contains(" ED25519 ") {
            disabled = true;
            in_block = true;
        }

        // ─── Config-line detection ──────────────────────────────────
        // C `keys.c:40`: `!strncasecmp(buf, "Ed25519PublicKey", 16)
        // && strchr(" \t=", buf[16])`. Prefix-16-case-insensitive
        // then delim-at-16.
        //
        // `strchr(" \t=", c)` returns non-null iff c ∈ {' ', '\t',
        // '='}. NOT c == '\0' — `strchr` finds the terminator only if
        // you ask for `'\0'`, and here `buf[16]` of a line that has
        // exactly 16 chars before the newline is `'\n'`, not `'\0'`
        // (fgets keeps the newline). So `Ed25519PublicKey\n` (line of
        // just the key name, no value) doesn't match. Good — that's
        // not a valid config line anyway (`tinc-conf` would reject:
        // key but no value).
        //
        // `eq_ignore_ascii_case` for the strncasecmp. `as_bytes()
        // .get(16)` for the delim — `get` because a short line indexes
        // OOB and we want false, not panic. C reads `buf[16]` even if
        // the line is short (it's reading into the 1024-byte buffer's
        // stale or zero-init contents) — undefined-ish, but in practice
        // the `strncasecmp` already failed for short lines so the `&&`
        // short-circuits. Our `len >= 16 && ...` is the explicit form.
        let pubkey_line = line.len() >= 17 // 16 + at-least-the-delim
            && line.as_bytes()[..16].eq_ignore_ascii_case(b"Ed25519PublicKey")
            && matches!(line.as_bytes()[16], b' ' | b'\t' | b'=');
        if pubkey_line {
            disabled = true;
        }

        // ─── Write (with # if disabled) ─────────────────────────────
        // C `keys.c:46-54`: `if(block || ed25519pubkey) fputc('#', w);
        // fputs(buf, w);`. The # goes before the whole line including
        // its newline, so `#-----BEGIN ...\n`. Exactly one byte
        // prepended.
        if in_block || pubkey_line {
            w.write_all(b"#").map_err(io_err(&tmp_path))?;
        }
        w.write_all(line.as_bytes()).map_err(io_err(&tmp_path))?;

        // ─── PEM block end detection ────────────────────────────────
        // C `keys.c:57`: AFTER the write. `if(block && !strncmp(buf,
        // "-----END ", 9))`. The END line itself gets the `#` (we
        // already wrote it above), and NEXT iteration `in_block` is
        // false. C doesn't check that the END type matches the BEGIN
        // type (`keys.c:57` just checks the prefix). Neither do we.
        if in_block && line.starts_with("-----END ") {
            in_block = false;
        }
    }

    // Flush before the perms/rename — `BufWriter::drop` flushes but
    // swallows errors. Explicit flush surfaces ENOSPC etc.
    w.flush().map_err(io_err(&tmp_path))?;
    drop(w); // close the fd before rename — not required on Unix, but clean

    // ─── If nothing was disabled, leave the original alone ──────────
    // C `keys.c:71-101`: the whole rename dance is inside
    // `if(disabled)`. The `else` branch (`keys.c:103`) just unlinks
    // the tmpfile. (We wrote a perfect copy, but rename-ing a copy
    // over the original is a no-op modulo inode/mtime — C avoids the
    // mtime bump, so do we.)
    if !disabled {
        // Guard's drop unlinks. Explicit drop here is redundant (it'd
        // happen at scope end) but makes the intent visible.
        drop(tmp_guard);
        return Ok(false);
    }

    // ─── Preserve mode, then atomic rename ──────────────────────────
    // C does mode-at-create via `fopenmask`. We do it now, just before
    // rename. See module doc "Mode preservation" for why the timing
    // difference doesn't matter.
    #[cfg(unix)]
    fs::set_permissions(&tmp_path, src_perms).map_err(io_err(&tmp_path))?;

    // Disarm the guard — rename consumes the tmpfile, unlink would race.
    tmp_guard.0 = None;

    // C `keys.c:90`: `if(rename(tmpfile, filename))` (inside `#else`,
    // i.e. non-Windows). Unix rename is atomic and clobbers the
    // destination. Exactly what we want.
    fs::rename(&tmp_path, path).map_err(io_err(path))?;

    Ok(true)
}

/// Unlink-on-drop. Disarmed by setting `.0 = None`.
///
/// Not `tempfile::NamedTempFile` — that picks a random name in a
/// system temp dir, but C uses `<path>.tmp` (same dir as the target,
/// for the rename to be atomic-on-same-fs). We could use
/// `NamedTempFile::new_in(path.parent())` but then the name isn't
/// `<path>.tmp` and a crash leaves a `tmp.XXXXXX` mystery file
/// instead of an obviously-stale `ed25519_key.priv.tmp`. Match C.
struct TmpGuard(Option<std::path::PathBuf>);

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            // Best-effort. C `keys.c:76` ignores unlink's return too.
            let _ = fs::remove_file(p);
        }
    }
}

/// `O_WRONLY | O_CREAT | O_APPEND`. C `fopen("a")`.
///
/// The mode is the *create* mode — only matters if the file doesn't
/// exist. If it does (the rotation case), existing perms win. C
/// `fopenmask` does `fchmod` after open to force the mode regardless,
/// but only `if(perms & 0444)` (`fs.c:85`) — that's "if any read bit
/// is set", which is always (you'd never want a write-only key file).
/// So C *does* clamp on every genkey. We... don't. Intentional
/// deviation: if you `chmod 0400` your private key (read-only), genkey
/// shouldn't silently flip it back to 0600. C does flip it. The C
/// behavior is arguably a bug (it undoes your hardening); ours
/// respects it. Noted here so the diff is on purpose.
fn open_append(path: &Path, mode: u32) -> Result<fs::File, CmdError> {
    #[cfg(unix)]
    let opts = {
        let mut o = OpenOptions::new();
        o.append(true).create(true).mode(mode);
        o
    };
    #[cfg(not(unix))]
    let opts = {
        let _ = mode;
        let mut o = OpenOptions::new();
        o.append(true).create(true);
        o
    };
    opts.open(path).map_err(io_err(path))
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

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
    /// `strchr(" \t=", buf[16])`.
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

    /// Case-insensitive on the key name. `strncasecmp`.
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
    /// matched. The `strstr(buf, " ED25519 ")` is space-delimited.
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
    /// to the private key file: disable_old_keys, then append a fresh
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
            let f = open_append(&path, 0o600).unwrap();
            let mut w = BufWriter::new(f);
            write_pem(&mut w, TY_PRIVATE, &sk1.to_blob()).unwrap();
            w.flush().unwrap();
        }
        // File has one PEM block.
        let blob1 = read_pem(fs::File::open(&path).unwrap(), TY_PRIVATE, 96).unwrap();
        assert_eq!(&blob1[..], &sk1.to_blob()[..]);

        // Round 2: rotate.
        let sk2 = keypair::generate();
        {
            assert!(disable_old_keys(&path).unwrap()); // sk1's block disabled
            let f = open_append(&path, 0o600).unwrap();
            let mut w = BufWriter::new(f);
            write_pem(&mut w, TY_PRIVATE, &sk2.to_blob()).unwrap();
            w.flush().unwrap();
        }

        // File now has #-block then live block. read_pem gets the live one.
        let blob2 = read_pem(fs::File::open(&path).unwrap(), TY_PRIVATE, 96).unwrap();
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
