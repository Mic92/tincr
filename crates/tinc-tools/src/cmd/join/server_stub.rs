//! In-process server stub — test seam + daemon seed.

use std::fs;

use tinc_crypto::invite::COOKIE_LEN;
use tinc_crypto::sign::SigningKey;

use crate::cmd::{CmdError, io_err};
use crate::names::{Paths, check_id};

use super::finalize::parse_name_line;

/// What the daemon's `receive_invitation_sptps` does, minus daemon
/// state.
///
/// This is the *seed* for the daemon's invitation handler (per the
/// plan). The daemon version will take `&mut Connection` instead of
/// `&Paths`, and the `name` extracted from the file will go into
/// `c->name`. But the cookie→filename recovery, the rename-to-.used,
/// the file read, the Name validation — same code. When the daemon
/// lands, this function moves to `tincd::auth` mostly unchanged.
///
/// Exposed `pub(crate)` for the in-process roundtrip test. NOT
/// `myself`-aware: the caller passes `myname`; the daemon checks
/// `!strcmp(name, myself->name)` and bails (you can't invite
/// yourself).
///
/// `now` parameterized for tests (the expiry check).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn server_receive_cookie(
    paths: &Paths,
    inv_key: &SigningKey,
    cookie: &[u8; COOKIE_LEN],
    myname: &str,
    now: std::time::SystemTime,
) -> Result<(Vec<u8>, String, std::path::PathBuf), CmdError> {
    use tinc_crypto::invite::cookie_filename;

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
        if e.kind() == std::io::ErrorKind::NotFound {
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
    let deadline = now
        .checked_sub(crate::cmd::invite::EXPIRY)
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
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
    let first_line = std::str::from_utf8(first_line)
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
