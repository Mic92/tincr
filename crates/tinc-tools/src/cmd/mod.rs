//! Subcommand implementations for the `tinc` CLI.
//!
//! Each module is one `cmd_*` function from `tincctl.c`, ported. They
//! all take `&Paths` and return `Result<(), CmdError>`. The binary
//! (`bin/tinc.rs`) does the argv → command dispatch and the `CmdError`
//! → exit-code mapping.
//!
//! ## Why one module per command, not one big file
//!
//! `tincctl.c` is 3380 lines because every `cmd_*` function lives in
//! one TU. They share almost nothing — `cmd_init` and `cmd_dump` have
//! zero overlap. The Rust convention of one module per logical unit
//! actually helps here: `cmd/init.rs` is self-contained, you can read
//! it without paging through `cmd_dump`.

use std::io;
use std::path::PathBuf;

pub mod config;
pub mod ctl_simple;
pub mod dump;
pub mod edit;
pub mod exchange;
pub mod fsck;
pub mod genkey;
pub mod info;
pub mod init;
pub mod invite;
pub mod join;
pub mod network;
pub mod sign;
pub mod start;
pub mod stream;
pub mod top;

/// Unified error for all `cmd_*` functions. Preserves the message
/// for the binary to print, plus a structured kind for tests to
/// match on.
///
/// Phrasing matches upstream's error strings — not because they're
/// API (nothing parses them), but because users grep for error
/// messages, and matching upstream means existing forum posts /
/// stack overflow answers still apply.
#[derive(Debug, thiserror::Error)]
pub enum CmdError {
    /// File/dir already exists when we wanted to create it. `cmd_init`:
    /// `tinc.conf` already there → bail.
    #[error("Configuration file {} already exists!", .0.display())]
    Exists(PathBuf),

    /// Filesystem operation failed. `mkdir`, `open`, `write`, `chmod`.
    /// The path is what we were operating on; `io::Error` carries errno.
    #[error("Could not access {}: {err}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        err: io::Error,
    },

    /// User input failed validation. `check_id` returned false, name
    /// was empty, etc.
    #[error("{0}")]
    BadInput(String),

    /// Required positional argument missing. We always fail (no
    /// interactive prompts — see `init.rs` doc for why).
    #[error("No {0} given!")]
    MissingArg(&'static str),

    #[error("Too many arguments!")]
    TooManyArgs,
}

/// `CtlError` → `CmdError::BadInput` via `Display`. Daemon-communication
/// errors are user-facing — the CLI prints them and exits 1. The
/// `BadInput` variant is the "tell the user, no errno" bucket.
///
/// Why `BadInput` not a new `CmdError::Daemon`: `BadInput` already has
/// the "string message → exit 1" semantics every caller wants. A
/// separate variant would route to the same place. If we later want a
/// different exit code for daemon-down (so scripts can distinguish),
/// then we add the variant. YAGNI for now.
impl From<crate::ctl::CtlError> for CmdError {
    fn from(e: crate::ctl::CtlError) -> Self {
        CmdError::BadInput(e.to_string())
    }
}

/// `mkdir`, but EEXIST → chmod-and-succeed.
///
/// The chmod-on-exists is the surprising part. Why: if you previously
/// made `/etc/tinc` with shell `mkdir` (mode 0777 from your umask),
/// running `tinc init` should clamp it to 0755. Paranoia about
/// overly-permissive existing dirs.
///
/// Not `create_dir_all` — we want explicit control over each level's
/// mode (`confdir` 0755 vs `invitations/` 0700), and `create_dir_all`
/// doesn't take a mode.
///
/// Shared by init (confbase tree) and invite (invitations/ at 0700).
/// Lifted from init.rs when invite landed; the test
/// (`init::tests::makedir_clamps_mode`) stayed where it was — it tests
/// a property init depends on.
pub(crate) fn makedir(path: &std::path::Path, mode: u32) -> Result<(), CmdError> {
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        match fs::DirBuilder::new().mode(mode).create(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_err(path))
            }
            Err(e) => Err(io_err(path)(e)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        match std::fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(io_err(path)(e)),
        }
    }
}

/// How `open_nofollow` should create the file. Covers the three
/// `OpenOptions` recipes the cmd layer actually uses.
#[derive(Clone, Copy)]
pub(crate) enum OpenKind {
    /// `O_WRONLY | O_CREAT | O_TRUNC` — clobber.
    CreateTrunc,
    /// `O_WRONLY | O_CREAT | O_EXCL` — fail if it exists.
    CreateExcl,
    /// `O_WRONLY | O_CREAT | O_APPEND` — add to the end.
    Append,
}

/// Open `path` with `O_NOFOLLOW`, the requested create semantics, and
/// (on Unix) the given create mode. `mode` is only consulted when the
/// file is actually created; pass `0o666` for the libc default.
///
/// Centralises the `OpenOptions` + `cfg(unix)` + `OpenOptionsExt`
/// dance that used to be open-coded at every key/host-file write site.
pub(crate) fn open_nofollow(
    path: &std::path::Path,
    kind: OpenKind,
    mode: u32,
) -> Result<std::fs::File, CmdError> {
    let mut o = std::fs::OpenOptions::new();
    match kind {
        OpenKind::CreateTrunc => {
            o.write(true).create(true).truncate(true);
        }
        OpenKind::CreateExcl => {
            o.write(true).create_new(true);
        }
        OpenKind::Append => {
            o.append(true).create(true);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
    }
    #[cfg(not(unix))]
    let _ = mode;
    o.open(path).map_err(io_err(path))
}

/// `File::create` + `O_NOFOLLOW` (truncate, create, no symlink follow).
pub(crate) fn create_nofollow(path: &std::path::Path) -> Result<std::fs::File, CmdError> {
    open_nofollow(path, OpenKind::CreateTrunc, 0o666)
}

pub(crate) fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> CmdError {
    let path = path.into();
    move |err| CmdError::Io { path, err }
}
