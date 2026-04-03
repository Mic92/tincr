//! Daemon-side invitation handler. `protocol_auth.c:119-310`.
//!
//! ## Flow (after `id_h` recognizes the `?` greeting)
//!
//! 1. Daemon: `Sptps::start(Responder, Stream, invitation_key,
//!    joiner_throwaway_pubkey, "tinc invitation", 15)`. Label
//!    is 15 bytes — NOT NUL-terminated (unlike the meta-conn
//!    label, see `proto.rs::tcp_label_has_trailing_nul`).
//! 2. Handshake → joiner sends type-0 record, 18 bytes = cookie.
//! 3. We recover filename via `cookie_filename(cookie, inv_key.
//!    pub())`, atomic-rename to `.used`, stat for expiry,
//!    read file, parse first-line `Name = X`.
//! 4. Send file contents as type-0 records (chunked at 1024 —
//!    `protocol_auth.c:294-303`). Send empty type-1 = "file done".
//! 5. Joiner sends type-1 = base64 pubkey string.
//! 6. We write `hosts/{name}` with `Ed25519PublicKey = {pubkey}`,
//!    add the conn's addr to addrcache, run `invitation-accepted`.
//! 7. Send empty type-2 = "ack". Joiner closes.
//!
//! ## State machine
//!
//! Two states (the C's `c->status.invitation_used` bool):
//! - `WaitingCookie`: only type-0 len=18 accepted (`:196`).
//! - `WaitingPubkey`: only type-1 accepted (`:192`). type-128
//!   (`HandshakeDone`) swallowed in both (`:188`).
//!
//! Anything else → close conn (`return false`).
//!
//! ## Why a separate module
//!
//! The cookie→file→read logic is testable without a daemon.
//! `serve_cookie` is `(confbase, &SigningKey, &[u8;18], myname,
//! lifetime, now) → Result<(Vec<u8>, String, PathBuf), ServeError>`.
//! The daemon calls it from the type-0 record arm; pumps the file
//! out; transitions to `WaitingPubkey`. The pubkey-write half
//! (`finalize`) is similarly standalone.
//!
//! ## Hoist provenance
//!
//! `serve_cookie` is `tinc-tools/src/cmd/join.rs::server_receive_
//! cookie` nearly verbatim. That function was deliberately written as
//! the daemon seed (per its doc-comment). The daemon can't depend on
//! tinc-tools (wrong direction: tools→daemon, not daemon→tools), so
//! the function is duplicated here. Factor trigger is "a third crate
//! needs this" — there isn't one. The hoisted bits: `split_var`,
//! `parse_name_line`, the rename-stat-read-validate body.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tinc_conf::read_pem;
use tinc_crypto::invite::cookie_filename;

/// Re-exported for `daemon::dispatch_invitation_outputs`. The 18-byte
/// cookie length — `protocol_auth.c:196`: `if(len != 18)`.
pub use tinc_crypto::invite::COOKIE_LEN;
use tinc_crypto::sign::SigningKey;
use tinc_proto::check_id;

// On-disk private blob: `expanded[64] || public[32]`. Same constant as
// `keys.rs::PRIVATE_BLOB_LEN`. Not re-exported from there because keys.rs
// keeps it module-local; the dup is two lines.
const PRIVATE_BLOB_LEN: usize = 96;
const TY_PRIVATE: &str = "ED25519 PRIVATE KEY";

/// File chunk size for SPTPS type-0 records. `protocol_auth.c:294`:
/// `char buf[1024]`. The SPTPS record max is much larger (64 KiB);
/// 1024 is just the C's arbitrary `fread` buffer. We match it for
/// wire-shape parity in case anybody is counting records.
pub const CHUNK_SIZE: usize = 1024;

/// State carried on `Connection` between SPTPS records. The C's
/// `c->status.invitation_used` + `c->name` (after the cookie
/// arrives, `c->name` = the invited node's name).
#[derive(Debug)]
pub enum InvitePhase {
    /// `protocol_auth.c:196`: `if(type != 0 || len != 18) return false`.
    WaitingCookie,
    /// File sent; `c->name` known. `c->status.invitation_used = true`.
    /// Carries the `.used` file path so the daemon can unlink it after
    /// `finalize` succeeds (`:305`).
    WaitingPubkey { name: String, used_path: PathBuf },
}

#[derive(Debug)]
pub enum ServeError {
    /// `protocol_auth.c:217-223`. Cookie didn't match any file.
    /// Single-use: an already-used cookie also lands here — the
    /// `.used` rename makes the original ENOENT.
    NonExisting,
    /// `protocol_auth.c:230-237`. `mtime + lifetime < now`.
    Expired,
    /// `protocol_auth.c:277`. First line isn't `Name = <valid-id>`,
    /// or name equals myself.
    BadInvitationFile(String),
    /// `protocol_auth.c:125`. Joiner pubkey has newline. Config-
    /// injection attempt: `"evil\nPort = 0"` would become two lines
    /// in `hosts/{name}`, the second a real config var.
    BadPubkey,
    /// `protocol_auth.c:131`. `hosts/{name}` exists. Don't overwrite:
    /// if a previous join half-completed or an attacker pre-populated
    /// `hosts/`, we'd replace a known key with the attacker's.
    HostFileExists(PathBuf),
    /// fs failures (open, read, write, stat).
    Io { path: PathBuf, err: std::io::Error },
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonExisting => write!(f, "non-existing or already-used invitation"),
            Self::Expired => write!(f, "expired invitation"),
            Self::BadInvitationFile(s) => write!(f, "invalid invitation file: {s}"),
            Self::BadPubkey => write!(f, "invalid public key from invited node"),
            Self::HostFileExists(p) => {
                write!(f, "host config file {} already exists", p.display())
            }
            Self::Io { path, err } => write!(f, "I/O error on {}: {err}", path.display()),
        }
    }
}

impl std::error::Error for ServeError {}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> ServeError + '_ {
    move |err| ServeError::Io {
        path: path.to_owned(),
        err,
    }
}

/// `read_invitation_key` (`keys.c` analog). Load
/// `confbase/invitations/ed25519_key.priv`. The C loads this in
/// `setup_myself_reloadable` (`net_setup.c`); the daemon holds it as
/// `Option<SigningKey>` (None = no invitations outstanding, the `?`
/// greeting is rejected at `id_h`).
///
/// `Ok(None)` if the file doesn't exist (not an error — just no
/// invites issued yet). `Err` for read/parse failures (file exists
/// but is corrupt — that IS an error, the operator needs to know).
///
/// # Errors
/// `Io` for fs failures other than ENOENT; `BadInvitationFile` for
/// PEM parse failures (re-using the variant; the message is in the
/// payload).
pub fn read_invitation_key(confbase: &Path) -> Result<Option<SigningKey>, ServeError> {
    let path = confbase.join("invitations").join("ed25519_key.priv");
    let f = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(ServeError::Io { path, err }),
    };
    let blob = read_pem(f, TY_PRIVATE, PRIVATE_BLOB_LEN)
        .map_err(|e| ServeError::BadInvitationFile(format!("invitation key PEM: {e}")))?;
    let mut arr = [0u8; PRIVATE_BLOB_LEN];
    arr.copy_from_slice(&blob);
    Ok(Some(SigningKey::from_blob(&arr)))
}

// ─── Hoisted from tinc-tools/src/cmd/join.rs ───────────────────────

/// The C tokenizer for `Key = Value` lines. `strcspn(l, "\t =")` then
/// `strspn` past `\t `, then optionally `=`, then `strspn` past `\t `
/// again. `protocol_auth.c:255-275` has its own copy of this logic
/// inline; tinc-tools has it in `cmd::join::split_var`. Hoisted.
///
/// `Port = 655` → `("Port", "655")`. `Port=655` → `("Port", "655")`.
/// `Port` → `("Port", "")`. Empty/ws-only → `None`.
fn split_var(line: &str) -> Option<(&str, &str)> {
    let key_end = line.find(['\t', ' ', '=']).unwrap_or(line.len());
    let key = &line[..key_end];
    if key.is_empty() {
        return None;
    }
    let rest = &line[key_end..];
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let val = rest.trim_start_matches([' ', '\t']);
    Some((key, val))
}

/// First-line parser: `Name = X` → `Some("X")`, else `None`.
/// `protocol_auth.c:255-277`.
fn parse_name_line(line: &str) -> Option<&str> {
    let (k, v) = split_var(line)?;
    if k.eq_ignore_ascii_case("Name") {
        Some(v)
    } else {
        None
    }
}

/// `receive_invitation_sptps` (`protocol_auth.c:196-310`): type-0
/// record handler.
///
/// Hoisted from `tinc-tools/src/cmd/join.rs::server_receive_cookie`
/// nearly verbatim — that function was deliberately written as the
/// daemon seed. Differences:
/// - Takes `&Path` confbase directly (no `Paths` struct — that's
///   tinc-tools's thing).
/// - Error type is local (`ServeError`, was `CmdError`).
/// - `invitation_lifetime` is a parameter (was hardcoded week).
///
/// Returns `(file_contents, invited_name, used_path)`. The caller
/// (daemon's record-dispatch) chunks `file_contents` over SPTPS as
/// type-0 records via [`chunk_file`], sends empty type-1, transitions
/// to `InvitePhase::WaitingPubkey { name, used_path }`.
///
/// `now` parameterized for tests.
///
/// # Errors
/// - `NonExisting`: rename failed with ENOENT — no such cookie, or
///   already used. Single-use is enforced HERE by the atomic rename:
///   no check-then-rename, the rename IS the check.
/// - `Expired`: mtime older than `now - invitation_lifetime`. The
///   `.used` file is left in place (the C doesn't clean it up either;
///   expired invites are evidence).
/// - `BadInvitationFile`: first line doesn't parse as `Name = X`, or
///   `X` fails `check_id`, or `X == myname`. The `.used` file is left
///   in place (rename happened before the read; the C doesn't undo).
/// - `Io`: any other fs failure.
pub fn serve_cookie(
    confbase: &Path,
    inv_key: &SigningKey,
    cookie: &[u8; COOKIE_LEN],
    myname: &str,
    invitation_lifetime: Duration,
    now: SystemTime,
) -> Result<(Vec<u8>, String, PathBuf), ServeError> {
    // C `protocol_auth.c:201-207`: recover filename from cookie+key.
    // KAT-tested in tinc-crypto::invite — same composition `tinc
    // invite` used to *name* the file.
    let filename = cookie_filename(cookie, inv_key.public_key());
    let inv_dir = confbase.join("invitations");
    let inv_path = inv_dir.join(&filename);
    let used_path = inv_dir.join(format!("{filename}.used"));

    // C `protocol_auth.c:216-223`: atomic rename to .used.
    // Single-use: a second join with the same cookie hits ENOENT
    // here. The .used file is unlinked at the end (`:305`); if the
    // daemon crashes between rename and unlink, the .used file sits
    // there as evidence. (The expiry sweep in `tinc invite` skips it:
    // 24 chars + ".used" = 29, doesn't match the 24-char filter.)
    fs::rename(&inv_path, &used_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ServeError::NonExisting
        } else {
            ServeError::Io {
                path: inv_path,
                err: e,
            }
        }
    })?;

    // C `protocol_auth.c:226-237`: stat for mtime, check against
    // `now - invitation_lifetime`. Daemon reads `invitation_lifetime`
    // from config; default is a week (`protocol_auth.c:55`).
    let meta = fs::metadata(&used_path).map_err(io_err(&used_path))?;
    let mtime = meta.modified().map_err(io_err(&used_path))?;
    let deadline = now
        .checked_sub(invitation_lifetime)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    if mtime < deadline {
        return Err(ServeError::Expired);
    }

    // C `protocol_auth.c:240-257`: read first line, parse `Name = X`.
    // The C does this with a hand-rolled tokenizer. We read the whole
    // file (it's small — `tinc invite` caps it at a few KB) then
    // `parse_name_line` on line 1.
    let contents = fs::read(&used_path).map_err(io_err(&used_path))?;
    let first_line = contents
        .iter()
        .position(|&b| b == b'\n')
        .map_or(&contents[..], |i| &contents[..i]);
    let first_line = std::str::from_utf8(first_line)
        .map_err(|_| ServeError::BadInvitationFile("first line not UTF-8".into()))?;

    // C `protocol_auth.c:277`: `!*buf || !*name || strcasecmp(buf,
    // "Name") || !check_id(name) || !strcmp(name, myself->name)`.
    // All five checks collapse to one error.
    let invited_name = parse_name_line(first_line)
        .filter(|n| check_id(n))
        .filter(|n| *n != myname)
        .map(str::to_owned)
        .ok_or_else(|| {
            ServeError::BadInvitationFile(format!("first line not `Name = X`: {first_line:?}"))
        })?;

    Ok((contents, invited_name, used_path))
}

/// `finalize_invitation` (`protocol_auth.c:119-183`): type-1 record
/// handler. The fs-only half.
///
/// `pubkey_b64`: the joiner's pubkey, base64, no newline.
///
/// Writes `confbase/hosts/{name}` with `Ed25519PublicKey = {pk}\n`.
/// Returns the path written.
///
/// Does NOT do addrcache or the `invitation-accepted` script — those
/// need daemon state (`conn.addr` for addrcache, `Daemon` for script
/// env). The daemon calls this then handles addrcache + script + the
/// `.used` unlink + the type-2 send itself.
///
/// # Errors
/// - `BadPubkey` (`:125`): pubkey contains newline. **Security**: the
///   pubkey is interpolated verbatim into a config file; an embedded
///   newline would let the joiner inject arbitrary config vars
///   (`"evil\nAddress = attacker.example"` → two lines in `hosts/bob`).
/// - `HostFileExists` (`:131-134`): `hosts/{name}` already exists.
///   **Security**: if a previous join half-completed or an attacker
///   pre-populated `hosts/`, we'd overwrite a known key with the
///   attacker's. Hard fail. The C uses `fopen(..., "x")` for the same
///   atomic-create-exclusive semantics; we use `OpenOptions::create_
///   new(true)`.
/// - `Io`: write failures.
pub fn finalize(confbase: &Path, name: &str, pubkey_b64: &str) -> Result<PathBuf, ServeError> {
    // C `:122-126`: `if(strchr(data, '\n')) { ... return false; }`.
    if pubkey_b64.contains('\n') {
        return Err(ServeError::BadPubkey);
    }

    let host_path = confbase.join("hosts").join(name);

    // C `:131-134`: `FILE *f = fopen(filename, "w"); if(!f) ...`.
    // Wait — the C uses "w", not "x". But `:128-129` checks `access(
    // filename, F_OK)` first and bails if it exists. That's a TOCTOU
    // window. We close it: `create_new(true)` is `O_CREAT|O_EXCL` —
    // atomic create-or-fail. Same effect, no race.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&host_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ServeError::HostFileExists(host_path.clone())
            } else {
                ServeError::Io {
                    path: host_path.clone(),
                    err: e,
                }
            }
        })?;

    // C `:140`: `fprintf(f, "Ed25519PublicKey = %s\n", data)`.
    writeln!(f, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_path))?;

    Ok(host_path)
}

/// File chunking for SPTPS type-0 records. `protocol_auth.c:296-303`
/// reads `char buf[1024]` at a time with `fread`. The SPTPS record
/// max is 64 KiB; 1024 is the C's arbitrary `fread` buffer. We match
/// it for wire-shape parity (use [`CHUNK_SIZE`]).
///
/// Returns slices of at most `chunk_size` bytes. Empty input → empty
/// vec (the C `fread` loop never iterates for an empty file).
///
/// # Panics
/// If `chunk_size == 0`. Don't do that.
#[must_use]
pub fn chunk_file(contents: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    assert!(chunk_size > 0, "chunk_size must be nonzero");
    contents.chunks(chunk_size).collect()
}

// ─── tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tinc_conf::write_pem;

    /// Hand-rolled tmpdir, per-test. Same pattern as keys.rs/addrcache.rs.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "tincd-invserve-{tag}-{:?}",
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_key() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32])
    }

    /// Set up a confbase with `invitations/{filename}` containing `body`.
    /// Returns (confbase, cookie). The filename is derived from cookie +
    /// `inv_key.public_key()` — same composition `tinc invite` uses.
    fn setup_invitation(tag: &str, inv_key: &SigningKey, body: &str) -> (TmpDir, [u8; COOKIE_LEN]) {
        let tmp = TmpDir::new(tag);
        let inv_dir = tmp.path().join("invitations");
        fs::create_dir_all(&inv_dir).unwrap();
        let cookie = [0x42u8; COOKIE_LEN];
        let filename = cookie_filename(&cookie, inv_key.public_key());
        fs::write(inv_dir.join(&filename), body).unwrap();
        (tmp, cookie)
    }

    const WEEK: Duration = Duration::from_secs(604_800);

    // ─── serve_cookie ──────────────────────────────────────────────

    #[test]
    fn serve_cookie_roundtrip() {
        let key = test_key();
        let body = "Name = bob\nAddress = 192.0.2.1\n";
        let (tmp, cookie) = setup_invitation("roundtrip", &key, body);

        let (contents, name, used_path) =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap();

        assert_eq!(contents, body.as_bytes());
        assert_eq!(name, "bob");

        // .used exists, original is gone.
        assert!(used_path.exists(), ".used file should exist");
        assert!(
            used_path.extension().is_some_and(|e| e == "used"),
            ".used path should end in .used"
        );
        let inv_dir = tmp.path().join("invitations");
        let filename = cookie_filename(&cookie, key.public_key());
        assert!(
            !inv_dir.join(&filename).exists(),
            "original invitation file should be renamed away"
        );
    }

    #[test]
    fn serve_cookie_nonexisting() {
        let key = test_key();
        let tmp = TmpDir::new("nonexisting");
        fs::create_dir_all(tmp.path().join("invitations")).unwrap();
        // Random cookie that doesn't match any file.
        let cookie = [0x99u8; COOKIE_LEN];

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::NonExisting));
    }

    /// Single-use enforcement: the rename IS the check. Second call
    /// hits ENOENT on the original filename. No separate "used" check
    /// — atomicity is the mechanism.
    #[test]
    fn serve_cookie_single_use() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("single-use", &key, "Name = bob\n");

        // First call succeeds.
        let (_, name, _) =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap();
        assert_eq!(name, "bob");

        // Second call: original file is gone (renamed to .used) → ENOENT
        // → NonExisting. Proves single-use is enforced by the rename,
        // not by a separate flag.
        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::NonExisting));
    }

    /// Expiry check. We don't mutate filesystem mtime; instead `now`
    /// is parameterized far into the future. File mtime is real
    /// `SystemTime::now()`; `serve_cookie`'s `now` is `mtime + WEEK +
    /// 1day`. Same effect, no `filetime`/`utimensat` dependency.
    #[test]
    fn serve_cookie_expired() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("expired", &key, "Name = bob\n");

        // now = real now + week + 1 day. The file's mtime is real-now
        // (we just wrote it), so mtime < now - week.
        let far_future = SystemTime::now() + WEEK + Duration::from_secs(86_400);

        let err = serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, far_future).unwrap_err();
        assert!(matches!(err, ServeError::Expired));

        // .used file should still exist — the C doesn't clean up
        // expired invites either; they're evidence.
        let inv_dir = tmp.path().join("invitations");
        let filename = cookie_filename(&cookie, key.public_key());
        assert!(inv_dir.join(format!("{filename}.used")).exists());
    }

    /// First line isn't `Name = ...` → BadInvitationFile. The .used
    /// file exists (rename happened before the parse; C doesn't undo).
    #[test]
    fn serve_cookie_bad_first_line() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("bad-first", &key, "Port = 655\nName = bob\n");

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::BadInvitationFile(_)));

        // .used file exists — rename succeeded, parse failed after.
        let inv_dir = tmp.path().join("invitations");
        let filename = cookie_filename(&cookie, key.public_key());
        assert!(inv_dir.join(format!("{filename}.used")).exists());
    }

    /// `Name = alice` when `myname = "alice"` → rejected. C `:277`:
    /// `!strcmp(name, myself->name)`. You can't invite yourself.
    #[test]
    fn serve_cookie_self_invite_rejected() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("self-invite", &key, "Name = alice\n");

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::BadInvitationFile(_)));
    }

    /// `Name = ../../evil` → check_id rejects it. Path-traversal defense.
    #[test]
    fn serve_cookie_bad_name_chars() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("bad-name", &key, "Name = ../etc/passwd\n");

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::BadInvitationFile(_)));
    }

    // ─── finalize ──────────────────────────────────────────────────

    #[test]
    fn finalize_writes_host_file() {
        let tmp = TmpDir::new("fin-write");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let path = finalize(tmp.path(), "bob", "abcDEF123_etc").unwrap();

        assert_eq!(path, tmp.path().join("hosts").join("bob"));
        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written, "Ed25519PublicKey = abcDEF123_etc\n");
    }

    /// Config injection defense. The pubkey is interpolated verbatim
    /// into `hosts/{name}`. If the joiner sends `"evil\nPort = 0"`,
    /// that becomes two config lines — the second a real var. Rejecting
    /// any newline closes that hole. C `protocol_auth.c:122-126`.
    #[test]
    fn finalize_rejects_newline() {
        let tmp = TmpDir::new("fin-newline");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let err = finalize(tmp.path(), "bob", "evil\nPort = 0").unwrap_err();
        assert!(matches!(err, ServeError::BadPubkey));

        // Nothing written.
        assert!(!tmp.path().join("hosts").join("bob").exists());
    }

    /// Don't-overwrite defense. C uses `access()` then `fopen("w")`
    /// (TOCTOU window); we use `O_CREAT|O_EXCL` (atomic). Either way:
    /// if `hosts/bob` exists, fail hard. Otherwise an attacker who can
    /// pre-populate `hosts/` could get their key recorded under the
    /// joiner's name.
    #[test]
    fn finalize_rejects_existing() {
        let tmp = TmpDir::new("fin-exists");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();
        let host = tmp.path().join("hosts").join("bob");
        fs::write(&host, "Ed25519PublicKey = original\n").unwrap();

        let err = finalize(tmp.path(), "bob", "attacker_key").unwrap_err();
        assert!(matches!(err, ServeError::HostFileExists(_)));

        // Pre-existing file unchanged.
        let after = fs::read_to_string(&host).unwrap();
        assert_eq!(after, "Ed25519PublicKey = original\n");
    }

    // ─── chunk_file ────────────────────────────────────────────────

    #[test]
    fn chunk_file_exact_multiple() {
        let data = vec![0xAAu8; 2048];
        let chunks = chunk_file(&data, 1024);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 1024);
        assert_eq!(chunks[1].len(), 1024);
    }

    #[test]
    fn chunk_file_with_remainder() {
        let data = vec![0xBBu8; 2049];
        let chunks = chunk_file(&data, 1024);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 1024);
        assert_eq!(chunks[1].len(), 1024);
        assert_eq!(chunks[2].len(), 1);
    }

    #[test]
    fn chunk_file_empty() {
        let data: &[u8] = &[];
        let chunks = chunk_file(data, 1024);
        assert!(chunks.is_empty());
    }

    // ─── read_invitation_key ───────────────────────────────────────

    #[test]
    fn read_invitation_key_missing() {
        let tmp = TmpDir::new("key-missing");
        // No invitations/ dir at all.
        let r = read_invitation_key(tmp.path()).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn read_invitation_key_valid() {
        let tmp = TmpDir::new("key-valid");
        let inv_dir = tmp.path().join("invitations");
        fs::create_dir_all(&inv_dir).unwrap();

        let key = test_key();
        let blob = key.to_blob();
        let f = File::create(inv_dir.join("ed25519_key.priv")).unwrap();
        write_pem(f, TY_PRIVATE, &blob).unwrap();

        let loaded = read_invitation_key(tmp.path()).unwrap().unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
    }

    // ─── split_var (hoisted parser sanity) ─────────────────────────

    #[test]
    fn split_var_forms() {
        assert_eq!(split_var("Name = bob"), Some(("Name", "bob")));
        assert_eq!(split_var("Name=bob"), Some(("Name", "bob")));
        assert_eq!(split_var("Name\tbob"), Some(("Name", "bob")));
        assert_eq!(split_var("Name"), Some(("Name", "")));
        assert_eq!(split_var(""), None);
        assert_eq!(split_var(" "), None);
        assert_eq!(split_var("=655"), None);
    }

    #[test]
    fn parse_name_line_case_insensitive() {
        assert_eq!(parse_name_line("Name = bob"), Some("bob"));
        assert_eq!(parse_name_line("name = bob"), Some("bob"));
        assert_eq!(parse_name_line("NAME = bob"), Some("bob"));
        assert_eq!(parse_name_line("Port = 655"), None);
    }
}
