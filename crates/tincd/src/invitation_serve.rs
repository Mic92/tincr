//! Daemon-side invitation handler.
//!
//! Flow: SPTPS handshake (label `"tinc invitation"`, 15 bytes, NOT
//! NUL-terminated) → type-0 cookie (18B) → atomic-rename to `.used`,
//! check expiry, parse `Name =` → send file (type-0, 1024B chunks) +
//! empty type-1 → receive type-1 pubkey → write `hosts/{name}` →
//! send empty type-2 ack.
//!
//! `serve_cookie`/`finalize` hoisted from `tinc-tools/src/cmd/
//! join.rs::server_receive_cookie`; can't dep on tinc-tools (wrong
//! direction). Factor trigger is a third crate — there isn't one.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tinc_conf::read_pem;
use tinc_crypto::invite::cookie_filename;

pub(crate) use tinc_crypto::invite::COOKIE_LEN;
use tinc_crypto::sign::SigningKey;
use tinc_proto::check_id;

// expanded[64] || public[32]. Same as keys.rs::PRIVATE_BLOB_LEN (module-local there).
const PRIVATE_BLOB_LEN: usize = 96;
const TY_PRIVATE: &str = "ED25519 PRIVATE KEY";

/// Chunk size matched for wire-shape parity with C tincd.
pub(crate) const CHUNK_SIZE: usize = 1024;

/// Invitation handshake phase.
#[derive(Debug)]
pub(crate) enum InvitePhase {
    /// type != 0 || len != 18 → close.
    WaitingCookie,
    /// `c->status.invitation_used = true`.
    WaitingPubkey { name: String },
    /// Post-ACK terminal state; any further record terminates the conn.
    Done,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ServeError {
    /// `:217-223`. Single-use: already-used cookie → ENOENT here too.
    #[error("non-existing or already-used invitation")]
    NonExisting,
    /// `:230-237`.
    #[error("expired invitation")]
    Expired,
    /// `:277`. First line isn't `Name = <valid-id>`, or name == myself.
    #[error("invalid invitation file: {0}")]
    BadInvitationFile(String),
    /// `:125`. Newline in pubkey = config-injection attempt.
    #[error("invalid public key from invited node")]
    BadPubkey,
    /// `:131`. Don't overwrite: would replace a known key.
    #[error("host config file {} already exists", .0.display())]
    HostFileExists(PathBuf),
    #[error("I/O error on {}: {err}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        err: std::io::Error,
    },
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> ServeError + '_ {
    move |err| ServeError::Io {
        path: path.to_owned(),
        err,
    }
}

/// `read_invitation_key` (`keys.c` analog). Load
/// `confbase/invitations/ed25519_key.priv`.
///
/// `Ok(None)` if the file doesn't exist (no invites yet). `Err` for
/// read/parse failures (corrupt — operator needs to know).
///
/// # Errors
/// `Io` for fs failures other than ENOENT; `BadInvitationFile` for
/// PEM parse failures.
pub(crate) fn read_invitation_key(confbase: &Path) -> Result<Option<SigningKey>, ServeError> {
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

/// Tokenizer for `Key = Value`. `Port = 655` → `("Port", "655")`.
/// `Port` → `("Port", "")`.
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

fn parse_name_line(line: &str) -> Option<&str> {
    let (k, v) = split_var(line)?;
    if k.eq_ignore_ascii_case("Name") {
        Some(v)
    } else {
        None
    }
}

/// `receive_invitation_sptps` type-0 handler. Returns
/// `(file_contents, invited_name, used_path)`.
///
/// # Errors
/// - `NonExisting`: rename ENOENT. Single-use is enforced BY the
///   atomic rename (no check-then-rename TOCTOU).
/// - `Expired`: `.used` file left in place (evidence; C same).
/// - `BadInvitationFile`: rename already happened; C doesn't undo.
pub(crate) fn serve_cookie(
    confbase: &Path,
    inv_key: &SigningKey,
    cookie: &[u8; COOKIE_LEN],
    myname: &str,
    invitation_lifetime: Duration,
    now: SystemTime,
) -> Result<(Vec<u8>, String, PathBuf), ServeError> {
    // :201-207
    let filename = cookie_filename(cookie, inv_key.public_key());
    let inv_dir = confbase.join("invitations");
    let inv_path = inv_dir.join(&filename);
    let used_path = inv_dir.join(format!("{filename}.used"));

    // :216-223 atomic rename. Single-use: second join → ENOENT.
    // Crash between rename and :305 unlink leaves .used as evidence
    // (`tinc invite` expiry sweep skips it: 29 chars ≠ 24-char filter).
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

    // :226-237 stat + expiry check
    let meta = fs::metadata(&used_path).map_err(io_err(&used_path))?;
    let mtime = meta.modified().map_err(io_err(&used_path))?;
    let deadline = now
        .checked_sub(invitation_lifetime)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    if mtime < deadline {
        return Err(ServeError::Expired);
    }

    // :240-257
    let contents = fs::read(&used_path).map_err(io_err(&used_path))?;
    let first_line = contents
        .iter()
        .position(|&b| b == b'\n')
        .map_or(&contents[..], |i| &contents[..i]);
    let first_line = std::str::from_utf8(first_line)
        .map_err(|_| ServeError::BadInvitationFile("first line not UTF-8".into()))?;

    // :277: five checks (Name, check_id, != myname) → one error
    let invited_name = parse_name_line(first_line)
        .filter(|n| check_id(n))
        .filter(|n| *n != myname)
        .map(str::to_owned)
        .ok_or_else(|| {
            ServeError::BadInvitationFile(format!("first line not `Name = X`: {first_line:?}"))
        })?;

    Ok((contents, invited_name, used_path))
}

/// `finalize_invitation`: type-1 handler.
/// Writes `hosts/{name}`. Addrcache/script/unlink/type-2 are daemon-side.
///
/// # Errors
/// - `BadPubkey` (`:125`): newline = config-injection (**security**).
/// - `HostFileExists`: don't overwrite (**security**: attacker could
///   replace a known key). We use `O_CREAT|O_EXCL` (no TOCTOU).
pub(crate) fn finalize(
    confbase: &Path,
    name: &str,
    pubkey_b64: &str,
) -> Result<PathBuf, ServeError> {
    use std::os::unix::fs::OpenOptionsExt;
    // Ed25519 pubkey: 32 bytes → exactly 43 chars of unpadded tinc-
    // base64. `b64::decode` rejects anything outside the union
    // alphabet (incl. '\n', '=', whitespace).
    if pubkey_b64.len() != 43
        || tinc_crypto::b64::decode(pubkey_b64)
            .is_none_or(|d| d.len() != tinc_crypto::sign::PUBLIC_LEN)
    {
        return Err(ServeError::BadPubkey);
    }

    let host_path = confbase.join("hosts").join(name);

    // :128-134. C: access() then fopen("w") — TOCTOU. We: O_CREAT|O_EXCL.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
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

    // :140
    writeln!(f, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_path))?;

    Ok(host_path)
}

/// Use [`CHUNK_SIZE`] for wire parity.
///
/// # Panics
/// If `chunk_size == 0`.
#[must_use]
pub(crate) fn chunk_file(contents: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    assert!(chunk_size > 0, "chunk_size must be nonzero");
    contents.chunks(chunk_size).collect()
}

// ─── tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tinc_conf::write_pem;

    use crate::testutil::TmpDir;

    fn test_key() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32])
    }

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
        let cookie = [0x99u8; COOKIE_LEN];

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::NonExisting));
    }

    /// Single-use: rename IS the check (atomic, no TOCTOU).
    #[test]
    fn serve_cookie_single_use() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("single-use", &key, "Name = bob\n");

        let (_, name, _) =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap();
        assert_eq!(name, "bob");

        // Second call: original gone → ENOENT → NonExisting.
        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::NonExisting));
    }

    /// Expiry: parameterize `now` into the future (no mtime mutation).
    #[test]
    fn serve_cookie_expired() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("expired", &key, "Name = bob\n");

        let far_future = SystemTime::now() + WEEK + Duration::from_secs(86_400);

        let err = serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, far_future).unwrap_err();
        assert!(matches!(err, ServeError::Expired));

        // .used left in place (evidence; C same)
        let inv_dir = tmp.path().join("invitations");
        let filename = cookie_filename(&cookie, key.public_key());
        assert!(inv_dir.join(format!("{filename}.used")).exists());
    }

    /// .used exists (rename before parse; C doesn't undo).
    #[test]
    fn serve_cookie_bad_first_line() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("bad-first", &key, "Port = 655\nName = bob\n");

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::BadInvitationFile(_)));

        let inv_dir = tmp.path().join("invitations");
        let filename = cookie_filename(&cookie, key.public_key());
        assert!(inv_dir.join(format!("{filename}.used")).exists());
    }

    /// C :277: `!strcmp(name, myself->name)`.
    #[test]
    fn serve_cookie_self_invite_rejected() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("self-invite", &key, "Name = alice\n");

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::BadInvitationFile(_)));
    }

    /// `check_id` path-traversal defense.
    #[test]
    fn serve_cookie_bad_name_chars() {
        let key = test_key();
        let (tmp, cookie) = setup_invitation("bad-name", &key, "Name = ../etc/passwd\n");

        let err =
            serve_cookie(tmp.path(), &key, &cookie, "alice", WEEK, SystemTime::now()).unwrap_err();
        assert!(matches!(err, ServeError::BadInvitationFile(_)));
    }

    // ─── finalize ──────────────────────────────────────────────────

    /// Valid 43-char tinc-base64 of a 32-byte pubkey.
    fn valid_pubkey_b64() -> String {
        let pk = [0x11u8; 32];
        let s = tinc_crypto::b64::encode(&pk);
        assert_eq!(s.len(), 43);
        s
    }

    #[test]
    fn finalize_writes_host_file() {
        let tmp = TmpDir::new("fin-write");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk = valid_pubkey_b64();
        let path = finalize(tmp.path(), "bob", &pk).unwrap();

        assert_eq!(path, tmp.path().join("hosts").join("bob"));
        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written, format!("Ed25519PublicKey = {pk}\n"));
    }

    /// Config injection: newline → two config lines.
    #[test]
    fn finalize_rejects_newline() {
        let tmp = TmpDir::new("fin-newline");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let err = finalize(tmp.path(), "bob", "evil\nPort = 0").unwrap_err();
        assert!(matches!(err, ServeError::BadPubkey));
        assert!(!tmp.path().join("hosts").join("bob").exists());
    }

    #[test]
    fn finalize_rejects_bad_pubkey_shapes() {
        let tmp = TmpDir::new("fin-shape");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let good = valid_pubkey_b64();
        let too_long = format!("{good}A");
        // 43 chars but '=' is not in the union alphabet.
        let bad_charset = format!("{}=", &good[..42]);

        for bad in [&good[..42], too_long.as_str(), bad_charset.as_str()] {
            let err = finalize(tmp.path(), "bob", bad).unwrap_err();
            assert!(matches!(err, ServeError::BadPubkey), "{bad:?}: {err:?}");
            assert!(!tmp.path().join("hosts").join("bob").exists());
        }

        finalize(tmp.path(), "bob", &good).unwrap();
    }

    #[test]
    fn finalize_rejects_existing() {
        let tmp = TmpDir::new("fin-exists");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();
        let host = tmp.path().join("hosts").join("bob");
        fs::write(&host, "Ed25519PublicKey = original\n").unwrap();

        let err = finalize(tmp.path(), "bob", &valid_pubkey_b64()).unwrap_err();
        assert!(matches!(err, ServeError::HostFileExists(_)));
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
