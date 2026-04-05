//! `cmd_fsck` — configuration sanity checker.
//!
//! Four independent checks, one of which mutates with `--force`:
//!
//! | # | Check | `--force` |
//! |---|---|---|
//! | 1 | Keypair coherence: priv-derived pubkey matches `hosts/NAME`'s | rewrites pubkey |
//! | 2 | Per-variable validity: known/obsolete/wrong-file/duplicate | nothing — warnings only |
//! | 3 | Script executability: `*-up`/`*-down` have `+x` | `chmod 0755` |
//! | 4 | Private key file mode: `0600` | `chmod & ~077` |
//!
//! ## What we drop vs upstream
//!
//! - **All RSA** — `DISABLE_LEGACY` is permanent. The RSA pubkey
//!   check, the RSA roundtrip test, the RSA fix prompt, the
//!   `KEY_RSA`/`KEY_BOTH` enum branches: gone. ~150 LOC.
//!
//! - **The interactive prompt** — upstream reads `y/n` from stdin.
//!   Same deviation as `init`/`genkey`: we never prompt; the prompt
//!   collapses to `force`. Upstream gates on `isatty(0) && isatty(1)`
//!   so it also never prompts under a test harness — same observable
//!   behavior.
//!
//! - **The "private key does not work" branch** — the helper it
//!   guards is `xmalloc` + `b64encode` and cannot fail; the check is
//!   dead code. Dropped.
//!
//! - **`exe_name`/`print_tinc_cmd` reconstruction** — upstream
//!   reconstructs the invocation from globals. We take an opaque
//!   `cmd_prefix: &str` the binary constructs once.
//!
//! ## The testable seam: `Finding` + `Report`
//!
//! Upstream interleaves `fprintf(stderr, ...)` with `chmod`/append.
//! We collect findings into a `Vec` so tests can assert without
//! parsing stderr. Fixes still apply during the scan (later checks
//! may read the changed state) and are also recorded as `Finding`s.
//! `Finding` is NOT `PartialEq` (`PathBuf` equality is fragile);
//! tests `matches!` on variant + `path.ends_with(...)`.
//!
//! ## `success = success & check_scripts_and_configs()`
//!
//! Bitwise `&` not `&&`: all checks run regardless of earlier
//! failures. `Report::ok` is the AND of all results.
//!
//! ## fsck's pubkey fix writes PEM, not config-line
//!
//! The fix appends a PEM block, while `init`/`genkey` write
//! `Ed25519PublicKey = <b64>`. Both are valid (the loader falls back
//! to PEM). Preserved — the visual distinction ("repaired by fsck"
//! vs "init wrote this") is useful.
//!
//! ## `Ed25519PrivateKeyFile` config respect
//!
//! fsck reads the merged config tree, so it respects this var.
//! genkey/sign use `paths.ed25519_private()` directly and don't —
//! correct for genkey (creates default location), a sign bug noted
//! elsewhere.
//!
//! ## The hosts/ script suffix-strip-then-ignore
//!
//! Upstream's host-dir script check strips the suffix into a buffer
//! then never reads it. Dead code (copy-paste from the conf-dir
//! check which does validate the prefix). Dropped; same observable
//! behavior.

#![allow(clippy::doc_markdown)]

mod conf;
mod display;
mod keys;
mod scripts;

#[cfg(test)]
mod tests;

use std::fs;
use std::path::PathBuf;

use crate::cmd::CmdError;
use crate::cmd::exchange::get_my_name;
use crate::names::Paths;

use tinc_conf::{Source, read_server_config};

use conf::check_variables;
use keys::check_keypairs;
use scripts::check_scripts;

// Finding — one diagnostic or fix-result.
//
// Variants map roughly to upstream `fprintf(stderr, ...)` call sites.
// The goal is enough structure for tests to `matches!()` on without
// going stringly-typed, but not so much that adding a check means
// three new variants. Paths are carried for the variants that mention
// them in the message; tests check `path.ends_with()` not equality.
//
// Why not just `(Severity, String)`: tests would have to parse
// strings. Why not full structure (every field of every message):
// 30 variants for 18 message shapes, half of which are tested once.
// Middle ground: variant per *kind*, strings/paths as payload.

/// A single fsck diagnostic. Produced during the scan; the binary
/// formats them to stderr. Tests `matches!` on the variant.
#[derive(Debug)]
pub enum Finding {
    // ─── Fatal: no point continuing keypair check
    /// `tinc.conf` doesn't exist.
    TincConfMissing,
    /// `tinc.conf` exists but `access(R_OK)` failed. Message differs
    /// based on `getuid() != 0`.
    TincConfDenied { running_as_root: bool },
    /// `tinc.conf` readable but no `Name =`. Same message for
    /// missing-Name and bad-Name.
    NoName,
    /// `read_server_config` or `read_host_config` failed *after*
    /// `tinc.conf` was confirmed readable. Parse error in `conf.d/`,
    /// hosts file unreadable, etc. The `String` is `tinc-conf`'s
    /// `ReadError` Display — already includes the path and line.
    ConfigReadFailed(String),
    /// `ed25519_key.priv` (or `Ed25519PrivateKeyFile`) doesn't exist
    /// or PEM-parse failed. Missing-file vs bad-PEM aren't
    /// distinguished at the fsck level.
    NoPrivateKey { path: PathBuf },

    // ─── Keypair coherence
    /// `hosts/NAME` has neither `Ed25519PublicKey =` nor a PEM block.
    /// Fixable.
    NoPublicKey { host_file: PathBuf },
    /// Priv-derived pubkey ≠ `hosts/NAME`'s pubkey. The most likely
    /// real-world cause: `tinc generate-ed25519-keys` ran but the
    /// user manually restored an old `hosts/NAME` from backup. Or
    /// copied a `hosts/NAME` from another node. Fixable.
    KeyMismatch { host_file: PathBuf },
    /// `hosts/NAME` exists but `access(R_OK)` failed. Warning only —
    /// keypair check still tries (might succeed via
    /// `Ed25519PublicKeyFile` pointing elsewhere, theoretically).
    HostFileUnreadable { host_file: PathBuf },

    // ─── File modes (Unix only)
    /// Private key file has mode `& 077 != 0` — group/other readable.
    /// Fixable iff `uid_match` (you can't chmod a file you don't own
    /// without root).
    UnsafeKeyMode {
        path: PathBuf,
        mode: u32,
        uid_match: bool,
    },

    // ─── Scripts
    /// `*-up`/`*-down` in confbase that isn't `tinc-`/`host-`/
    /// `subnet-`. Not fixable — fsck doesn't know what you intended.
    /// Upstream prints an explanation once (the `static bool
    /// explained` trick); we print it every time (simpler; the
    /// explanation is two lines, and you rarely have >1 unknown
    /// script).
    UnknownScript { path: PathBuf },
    /// Script exists but `access(R_OK | X_OK)` failed with `EACCES`.
    /// Fixable (`chmod 0755`).
    ScriptNotExecutable { path: PathBuf },
    /// Script `access` failed with a *non-EACCES* error. Probably
    /// ENOENT race (file deleted between `readdir` and `access`) or
    /// filesystem weirdness. Not fixable.
    ScriptAccessError { path: PathBuf, err: String },
    /// `opendir(confbase)` or `opendir(hosts/)` failed. The dir-level
    /// error; the script checks inside can't run. Contributes to
    /// `!ok`.
    DirUnreadable { path: PathBuf, err: String },

    // ─── Per-variable validity
    /// `VAR_OBSOLETE` flag set. The four known: `GraphDumpFile`,
    /// `PrivateKey`, `PublicKey`, `PublicKeyFile`. Not fixable —
    /// fsck doesn't delete config lines.
    ObsoleteVar { name: String, source: Source },
    /// Non-`VAR_SERVER` var in `tinc.conf` (or `conf.d/`). Probably
    /// `Port = 655` in `tinc.conf` — should be in `hosts/NAME`. The
    /// most common fsck warning in the wild.
    HostVarInServer { name: String, source: Source },
    /// Non-`VAR_HOST` var in `hosts/*`.
    ServerVarInHost { name: String, source: Source },
    /// Non-`VAR_MULTIPLE` var appears more than once. **The only
    /// place that surfaces silent-first-wins.** The
    /// `Config::lookup().next()` pattern means a second `Port = 999`
    /// is invisibly ignored — fsck is the canary.
    ///
    /// `where_` is `"tinc.conf"` for the server check or the node
    /// name for a host check. NOT a path. The duplicate spans the
    /// whole file so there's no single line number to print.
    DuplicateVar { name: String, where_: String },

    // ─── Fix results
    /// `chmod` succeeded.
    FixedMode { path: PathBuf },
    /// `disable_old_keys` + append-PEM-pubkey succeeded.
    FixedPublicKey { path: PathBuf },
    /// Tried to fix; the syscall failed. Carries the `io::Error`
    /// Display, not the structured error — it's terminal, nobody
    /// pattern-matches on *which* errno.
    FixFailed { path: PathBuf, err: String },
}

/// Severity for output formatting. NOT for `Report::ok` — that's
/// computed structurally during the scan (which checks failed), not
/// derived from severities post-hoc. The reason: `KeyMismatch` is
/// `Error` *unless* `--force` fixed it, in which case it's a warning
/// followed by `FixedPublicKey`. The severity is contextual; `ok` is
/// what actually happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    /// Fix-result messages. Printed without a prefix.
    Info,
}

impl Finding {
    /// `ERROR:` / `WARNING:` / (nothing) prefix.
    #[must_use]
    pub fn severity(&self) -> Severity {
        use Finding as F;
        match self {
            F::TincConfMissing
            | F::TincConfDenied { .. }
            | F::NoName
            | F::ConfigReadFailed(_)
            | F::NoPrivateKey { .. }
            | F::ScriptAccessError { .. }
            | F::DirUnreadable { .. }
            | F::FixFailed { .. } => Severity::Error,

            F::NoPublicKey { .. }
            | F::KeyMismatch { .. }
            | F::HostFileUnreadable { .. }
            | F::UnsafeKeyMode { .. }
            | F::UnknownScript { .. }
            | F::ScriptNotExecutable { .. }
            | F::ObsoleteVar { .. }
            | F::HostVarInServer { .. }
            | F::ServerVarInHost { .. }
            | F::DuplicateVar { .. } => Severity::Warning,

            F::FixedMode { .. } | F::FixedPublicKey { .. } => Severity::Info,
        }
    }

    /// Suggestion message for the findings that have one — "here's
    /// the command to fix this manually". `cmd_prefix` is the `tinc
    /// -c /path` part the binary formats.
    ///
    /// `None` for findings with no suggestion (most of them — the
    /// suggestions are only for "you have no key, run genkey" and
    /// "you have no config, run init").
    #[must_use]
    pub fn suggestion(&self, cmd_prefix: &str) -> Option<String> {
        match self {
            Finding::TincConfMissing => Some(format!(
                "No tinc configuration found. Create a new one with:\n\n  {cmd_prefix} init"
            )),
            Finding::NoPrivateKey { .. } => Some(format!(
                "You can generate a new Ed25519 keypair with:\n\n  {cmd_prefix} generate-ed25519-keys"
            )),
            _ => None,
        }
    }
}

// Report

/// Everything fsck found, plus the bottom-line exit code.
#[derive(Debug)]
pub struct Report {
    /// In scan order: tinc.conf existence → keypair → key mode →
    /// scripts → variables.
    pub findings: Vec<Finding>,
    /// `true` ↔ `EXIT_SUCCESS`. Computed as bitwise AND, no short
    /// circuit: each phase contributes a `bool`, final result is the
    /// AND. Warnings don't affect it; only the fatal checks (no
    /// tinc.conf, no priv key, unfixed mismatch).
    pub ok: bool,
}

// The scan

/// `fsck()`.
///
/// `force` is `--force`: apply fixes (chmod, rewrite pubkey) instead
/// of just warning. Upstream also has interactive `y/n` prompts when
/// `tty`; we don't (see module doc).
///
/// The scan is **side-effecting** when `force` is true. Tests that
/// pass `force: true` should expect their tempdir to be mutated.
///
/// # Errors
///
/// Never returns `Err` — fsck's whole job is to *report* errors, not
/// propagate them. `CmdError` is in the signature for consistency
/// with the dispatch table; the `Result` is always `Ok`.
///
/// (The one place we *could* `Err` is "internal invariant violated"
/// — e.g., `b64::encode` returning the wrong length. We `expect()`
/// those instead. If that fires, it's a bug, not a user-facing fsck
/// finding.)
#[allow(clippy::missing_panics_doc)] // see above re: expect on b64
pub fn run(paths: &Paths, force: bool) -> Result<Report, CmdError> {
    let mut findings = Vec::new();

    // ─── Phase 0: tinc.conf existence + Name
    // The `access(R_OK)` check distinguishes ENOENT (suggest `tinc
    // init`) from EACCES (suggest `sudo`). We check via metadata —
    // `access(2)` checks effective UID, `metadata` doesn't, but for
    // the common cases (file doesn't exist / you can't read it) the
    // difference is academic.
    let tinc_conf = paths.tinc_conf();
    let Ok(name) = get_my_name(paths) else {
        // get_my_name already wraps the error; we re-probe to
        // distinguish ENOENT from EACCES from no-Name.
        match fs::metadata(&tinc_conf) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                findings.push(Finding::TincConfMissing);
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                findings.push(Finding::TincConfDenied {
                    running_as_root: is_root(),
                });
            }
            _ => {
                // tinc.conf exists and is readable; get_my_name
                // failed for a different reason — no Name= line,
                // or replace_name rejected it.
                findings.push(Finding::NoName);
            }
        }
        // Early return: the remaining checks (keypair, scripts,
        // variables) all need either a name or a confbase that we
        // now know doesn't exist.
        return Ok(Report {
            findings,
            ok: false,
        });
    };

    // ─── Phase 1: read full config tree
    // `read_server_config && read_host_config`. The `&&`
    // short-circuits — if server config fails, host isn't read.
    //
    // `read_host_config` is `parse_file(hosts/NAME)` + merge — see
    // `tinc-conf::read_server_config` doc for why it's not a function.
    let host_file = paths.host_file(&name);
    let config_result = read_server_config(&paths.confbase).and_then(|mut cfg| {
        let host_entries = tinc_conf::parse_file(&host_file)?;
        cfg.merge(host_entries);
        Ok(cfg)
    });

    // Track keypair-phase success separately.
    let keypair_ok = match &config_result {
        Ok(cfg) => {
            // ─── Phase 2: keypair check
            check_keypairs(paths, cfg, &host_file, force, &mut findings)
        }
        Err(e) => {
            findings.push(Finding::ConfigReadFailed(e.to_string()));
            false
        }
    };

    // ─── Phase 3+4: scripts + variables
    // **Bitwise `&`, not `&&`** — "this check does not require
    // working configuration, so run it always". Even if Phase 2
    // failed, we still want script/variable diagnostics. Scripts
    // always run; variables run unless the config-read itself failed
    // (can't check vars in a tree we couldn't build).
    let scripts_ok = check_scripts(paths, force, &mut findings);

    // Variable check. Re-parses config — wasteful but harmless. The
    // alternative (separating the merged-for-keypair tree back into
    // its source files) is worse.
    check_variables(paths, &mut findings);

    Ok(Report {
        findings,
        // `scripts_ok` contributes; variable warnings never do
        // (they're warnings — `check_conffile` returns nothing).
        ok: keypair_ok & scripts_ok,
    })
}

// Platform helpers

#[cfg(unix)]
fn is_root() -> bool {
    nix::unistd::getuid().is_root()
}

#[cfg(not(unix))]
fn is_root() -> bool {
    // Windows: no `getuid`. Upstream's stub returns 0, which makes
    // `is_root()` always true. That changes which EACCES message
    // prints — minor. We pick false (the more cautious message).
    false
}
