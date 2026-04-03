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
pub mod stream;
pub mod top;

/// Unified error for all `cmd_*` functions. The `tincctl.c` convention
/// is `return 1` on any error after `fprintf(stderr, ...)`. This
/// preserves the message for the binary to print, plus a structured
/// kind for tests to match on.
///
/// Phrasing matches the C `fprintf` strings — not because they're
/// API (they aren't; nothing parses them), but because users grep
/// for error messages, and matching the C means existing forum posts
/// / stack overflow answers still apply.
#[derive(Debug, thiserror::Error)]
pub enum CmdError {
    /// File/dir already exists when we wanted to create it. `cmd_init`:
    /// `tinc.conf` already there → bail. C: `if(!access(tinc_conf, F_OK))`.
    #[error("Configuration file {} already exists!", .0.display())]
    Exists(PathBuf),

    /// Filesystem operation failed. `mkdir`, `open`, `write`, `chmod`.
    /// The path is what we were operating on; `io::Error` carries
    /// errno. C: `fprintf(stderr, "Could not X %s: %s", path, strerror(errno))`.
    #[error("Could not access {}: {err}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        err: io::Error,
    },

    /// User input failed validation. `check_id` returned false, name
    /// was empty, etc. C: `fprintf(stderr, "Invalid X!\n")`.
    #[error("{0}")]
    BadInput(String),

    /// Required positional argument missing. C: `if(argc < 2)` →
    /// prompt-on-tty or fail-on-pipe. We always fail (no interactive
    /// prompts — see `init.rs` doc for why).
    #[error("No {0} given!")]
    MissingArg(&'static str),

    /// Too many positional arguments. C: `if(argc > 2)`.
    #[error("Too many arguments!")]
    TooManyArgs,
}

/// Shorthand for the `?` boilerplate. The C does this inline with
/// `if(!f) { fprintf; return 1; }` after every fopen/mkdir; we factor
/// it once.
/// `fs.c` `makedir`: mkdir, but EEXIST → chmod-and-succeed.
///
/// C: `if(mkdir) { if(EEXIST) chmod; return; }` — the chmod-on-exists
/// is the surprising part. Why: if you previously made `/etc/tinc`
/// with `mkdir` (mode 0777 from your shell's umask), running `tinc
/// init` should clamp it to 0755. Paranoia about overly-permissive
/// existing dirs.
///
/// Not `create_dir_all` — we want explicit control over each level's
/// mode (`confdir` 0755 vs `invitations/` 0700 in `fs.c:43`), and
/// `create_dir_all` doesn't take a mode.
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
                // chmod-on-exists. C `chmod(path, mode)`.
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

pub(crate) fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> CmdError {
    let path = path.into();
    move |err| CmdError::Io { path, err }
}
