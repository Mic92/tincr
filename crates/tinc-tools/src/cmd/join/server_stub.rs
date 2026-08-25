//! In-process server stub — test seam + daemon seed.

use std::fs;

use tinc_crypto::invite::COOKIE_LEN;
use tinc_crypto::sign::SigningKey;

use crate::cmd::{CmdError, io_err};
use crate::names::{Paths, check_id};

use super::finalize::parse_name_line;
use crate::cmd::invite::EXPIRY;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::str;
use std::time::SystemTime;
use tinc_crypto::invite::cookie_filename;

/// The daemon's invitation handler minus daemon state: cookie → filename,
/// rename to `.used`, read, validate `Name`, with expiry against `now`.
/// `pub(crate)` for the in-process roundtrip test; the caller passes `myname`
/// since there is no `myself` here.
#[cfg_attr(not(test), expect(dead_code))]
pub(crate) fn server_receive_cookie(
    paths: &Paths,
    inv_key: &SigningKey,
    cookie: &[u8; COOKIE_LEN],
    myname: &str,
    now: SystemTime,
) -> Result<(Vec<u8>, String, PathBuf), CmdError> {
    // Recover filename from cookie+key. KAT-tested in
    // tinc-crypto::invite — this is the same composition `cmd_invite`
    // used to *name* the file.
    let filename = cookie_filename(cookie, inv_key.public_key());
    let inv_path = paths.invitations_dir().join(&filename);
    let used_path = paths.invitations_dir().join(format!("{filename}.used"));

    // Atomic rename to .used. Single-use: a second join with the
    // same cookie hits ENOENT here. The .used file is unlinked at
    // the end; if the daemon crashes between rename and unlink, the
    // .used file sits there as evidence. (The expiry sweep skips it:
    // 24 chars + ".used" = 29, doesn't match the 24-char filter.)
    fs::rename(&inv_path, &used_path).map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            CmdError::BadInput("non-existing invitation".into())
        } else {
            CmdError::Io {
                path: inv_path,
                err: e,
            }
        }
    })?;

    // stat for mtime, check against `now - invitation_lifetime`.
    // Daemon uses `invitation_lifetime` config var; we use the same
    // week default as the sweep.
    let meta = fs::metadata(&used_path).map_err(io_err(&used_path))?;
    let mtime = meta
        .modified()
        .map_err(|_| CmdError::BadInput("cannot read mtime".into()))?;
    let deadline = now.checked_sub(EXPIRY).unwrap_or(SystemTime::UNIX_EPOCH);
    if mtime < deadline {
        return Err(CmdError::BadInput("expired invitation".into()));
    }

    // Read first line, parse `Name = X`. We read the whole file
    // (it's small — invite caps it at a few KB) then `parse_name_line`
    // on line 1.
    let contents = fs::read(&used_path).map_err(io_err(&used_path))?;
    let first_line = contents
        .iter()
        .position(|&b| b == b'\n')
        .map_or(&contents[..], |i| &contents[..i]);
    let first_line = str::from_utf8(first_line)
        .map_err(|_| CmdError::BadInput("Invalid invitation file".into()))?;

    // `!*buf || !*name || strcasecmp(buf, "Name") || !check_id(name)
    // || !strcmp(name, myself->name)`. All five checks in one error.
    let chunk_name = parse_name_line(first_line)
        .filter(|n| check_id(n))
        .filter(|n| *n != myname)
        .map(str::to_owned)
        .ok_or_else(|| CmdError::BadInput("Invalid invitation file".into()))?;

    Ok((contents, chunk_name, used_path))
}
