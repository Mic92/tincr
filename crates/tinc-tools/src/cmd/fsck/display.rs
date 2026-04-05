//! `fmt::Display` for `Finding` — the user-facing message text.

use std::fmt;

use super::Finding;

/// Phrasing preserved from upstream for the same reason as
/// `CmdError::Display` — users grep error strings, forum posts
/// reference them. Minor deviations noted inline.
impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Finding as F;
        match self {
            // The suggestion (`tinc init`) is carried separately in
            // `Finding::suggestion()`.
            F::TincConfMissing => {
                write!(f, "cannot read tinc.conf: No such file or directory")
            }
            F::TincConfDenied { running_as_root } => {
                if *running_as_root {
                    // tinc.conf is owned by someone else and you're
                    // root — check the path components.
                    write!(
                        f,
                        "cannot read tinc.conf: Permission denied. Check the permissions of each component of the path."
                    )
                } else {
                    write!(
                        f,
                        "cannot read tinc.conf: Permission denied. You are currently not running tinc as root. Use sudo?"
                    )
                }
            }
            F::NoName => {
                // Upstream prints this twice (once in `read_node_name`,
                // once in `fsck()`). We don't.
                write!(f, "tinc cannot run without a valid Name.")
            }
            F::ConfigReadFailed(e) => {
                // tinc-conf's `ReadError` Display already includes
                // the path.
                write!(f, "{e}")
            }
            F::NoPrivateKey { path } => {
                // Path added — upstream doesn't print it (it's
                // implied), but it's free here and the user might have
                // set `Ed25519PrivateKeyFile` to something surprising.
                write!(f, "No Ed25519 private key found at {}.", path.display())
            }
            F::NoPublicKey { host_file } => {
                // Path added (same reasoning).
                write!(
                    f,
                    "No (usable) public Ed25519 key found in {}.",
                    host_file.display()
                )
            }
            F::KeyMismatch { host_file } => {
                // Path added.
                write!(
                    f,
                    "public and private Ed25519 keys do not match. Public key in {} does not correspond to the private key.",
                    host_file.display()
                )
            }
            F::HostFileUnreadable { host_file } => {
                write!(f, "cannot read {}", host_file.display())
            }
            F::UnsafeKeyMode {
                path,
                mode,
                uid_match,
            } => {
                // The mode is added — upstream doesn't show it but
                // `0640` vs `0644` tells you if it's group-read or
                // world-read at a glance.
                if *uid_match {
                    write!(
                        f,
                        "unsafe file permissions on {} (mode {:04o}).",
                        path.display(),
                        mode & 0o7777
                    )
                } else {
                    write!(
                        f,
                        "unsafe file permissions on {} (mode {:04o}). You are not running fsck as the same uid as the file owner.",
                        path.display(),
                        mode & 0o7777
                    )
                }
            }
            F::UnknownScript { path } => {
                // Upstream uses `static bool explained` to print the
                // explanation once. We always print it — two lines,
                // and >1 unknown script is rare.
                write!(
                    f,
                    "Unknown script {} found. The only scripts in the configuration directory executed by tinc are: tinc-up, tinc-down, host-up, host-down, subnet-up, subnet-down.",
                    path.display()
                )
            }
            F::ScriptNotExecutable { path } => {
                // Upstream prints the strerror; for EACCES that's
                // "Permission denied" which is implied by "cannot
                // execute". Dropped for terseness.
                write!(f, "cannot read and execute {}", path.display())
            }
            F::ScriptAccessError { path, err } => {
                // The non-EACCES path.
                write!(f, "cannot access {}: {err}", path.display())
            }
            F::DirUnreadable { path, err } => {
                write!(f, "cannot read directory {}: {err}", path.display())
            }
            F::ObsoleteVar { name, source } => {
                // Our `Source` Display is "on line N while reading
                // config file PATH" — slightly more verbose than
                // upstream's "%s line %d", same information.
                write!(f, "obsolete variable {name} {source}")
            }
            F::HostVarInServer { name, source } => {
                write!(f, "host variable {name} found in server config {source}")
            }
            F::ServerVarInHost { name, source } => {
                write!(f, "server variable {name} found in host config {source}")
            }
            F::DuplicateVar { name, where_ } => {
                // `where_` is `nodename ? nodename : "tinc.conf"` —
                // a name, not a path.
                write!(f, "multiple instances of variable {name} in {where_}")
            }
            F::FixedMode { path } => {
                // Past tense, no severity prefix.
                write!(f, "Fixed permissions of {}.", path.display())
            }
            F::FixedPublicKey { path } => {
                write!(f, "Wrote Ed25519 public key to {}.", path.display())
            }
            F::FixFailed { path, err } => {
                // Generic because the path tells you what we were
                // trying.
                write!(f, "could not fix {}: {err}", path.display())
            }
        }
    }
}
