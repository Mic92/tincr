//! `cmd_fsck` — `fsck.c` (679 LOC, ~500 after `DISABLE_LEGACY` strip).
//!
//! Four independent checks, one of which mutates with `--force`:
//!
//! | # | Check | C lines | `--force` |
//! |---|---|---|---|
//! | 1 | Keypair coherence: priv-derived pubkey matches `hosts/NAME`'s | `380-425`, `563-604` | rewrites pubkey |
//! | 2 | Per-variable validity: known/obsolete/wrong-file/duplicate | `122-193` | nothing — warnings only |
//! | 3 | Script executability: `*-up`/`*-down` have `+x` | `427-527` | `chmod 0755` |
//! | 4 | Private key file mode: `0600` | `205-227` | `chmod & ~077` |
//!
//! ## What we drop vs C
//!
//! - **All RSA** — `DISABLE_LEGACY` is permanent. `check_rsa_pubkey`,
//!   `test_rsa_keypair`, `ask_fix_rsa_public_key`, `KEY_RSA`/`KEY_BOTH`
//!   enum branches: gone. ~150 LOC. The `#ifdef DISABLE_LEGACY` blocks
//!   in `fsck.c` are exactly the deletions; we just take the `#ifdef`
//!   branch unconditionally.
//!
//! - **The interactive prompt** — `ask_fix()` (`fsck.c:38-65`) reads
//!   `y/n` from stdin. Same deviation as `init`/`genkey`: we never
//!   prompt; `ask_fix()` collapses to `force`. The C gates on
//!   `isatty(0) && isatty(1)` (`tincctl.c:3336`) so it also never
//!   prompts under a test harness — same observable behavior.
//!
//! - **`ecdsa_get_base64_public_key` failure path** (`fsck.c:384`) —
//!   the C function is `xmalloc` + `b64encode_tinc` and cannot fail;
//!   the check is dead code. Dropped.
//!
//! - **`exe_name`/`print_tinc_cmd` reconstruction** — C reconstructs
//!   the invocation from globals. We take an opaque `cmd_prefix: &str`
//!   the binary constructs once.
//!
//! ## The testable seam: `Finding` + `Report`
//!
//! C interleaves `fprintf(stderr, ...)` with `chmod`/append. We collect
//! findings into a `Vec` so tests can assert without parsing stderr.
//! Fixes still apply during the scan (later checks may read the
//! changed state) and are also recorded as `Finding`s. `Finding` is
//! NOT `PartialEq` (`PathBuf` equality is fragile); tests `matches!`
//! on variant + `path.ends_with(...)`.
//!
//! ## `success = success & check_scripts_and_configs()`
//!
//! Note `&` not `&&` (`fsck.c:672`): all checks run regardless of
//! earlier failures. `Report::ok` is the AND of all results.
//!
//! ## fsck's pubkey fix writes PEM, not config-line
//!
//! `ask_fix_ec_public_key` (`fsck.c:269`) appends a PEM block, while
//! `init`/`genkey` write `Ed25519PublicKey = <b64>`. Both are valid
//! (`keys.c:179-199` falls back to PEM). Preserved — the visual
//! distinction ("repaired by fsck" vs "init wrote this") is useful.
//!
//! ## `Ed25519PrivateKeyFile` config respect
//!
//! `read_ecdsa_private_key` (`keys.c:108`) checks this config var.
//! fsck reads the merged config tree, so it respects it. genkey/sign
//! use `paths.ed25519_private()` directly and don't — correct for
//! genkey (creates default location), a sign bug noted elsewhere.
//!
//! ## The hosts/ script suffix-strip-then-ignore (`fsck.c:511-518`)
//!
//! `check_script_hostdir` strips the suffix into `fname` then never
//! reads it. Dead code (copy-paste from `check_script_confdir` which
//! does validate the prefix). Dropped; same observable behavior.

#![allow(clippy::doc_markdown)]
// `run()` is long because fsck IS long — four independent checks
// stitched in sequence. Splitting it would mean four functions that
// each take `&mut Vec<Finding>` and return `bool`, called once each
// in fixed order. That's the C's structure, and it's not better.
#![allow(clippy::too_many_lines)]

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::cmd::CmdError;
use crate::cmd::exchange::get_my_name;
use crate::cmd::genkey::disable_old_keys;
use crate::keypair;
use crate::names::{Paths, check_id};

use tinc_conf::{Config, Source, VARS, VarFlags, lookup_var, read_server_config};
use tinc_crypto::b64;
use tinc_crypto::sign::PUBLIC_LEN;

/// PEM type string for public keys. Third declaration (after
/// `keypair.rs` and... actually `keypair.rs` is the only one with
/// `TY_PUBLIC`). Factoring 23 bytes of static string into a re-export
/// is more noise than help. `keypair.rs` doc has the same rationale
/// for `TY_PRIVATE`.
const TY_PUBLIC: &str = "ED25519 PUBLIC KEY";

// Finding — one diagnostic or fix-result.
//
// Variants map roughly to C `fprintf(stderr, ...)` call sites. The
// goal is enough structure for tests to `matches!()` on without going
// stringly-typed, but not so much that adding a check means three new
// variants. Paths are carried for the variants that mention them in
// the message; tests check `path.ends_with()` not equality.
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
    /// `tinc.conf` doesn't exist. `fsck.c:237` ENOENT branch.
    TincConfMissing,
    /// `tinc.conf` exists but `access(R_OK)` failed. `fsck.c:243`
    /// EACCES branch — message differs based on `getuid() != 0`.
    TincConfDenied { running_as_root: bool },
    /// `tinc.conf` readable but no `Name =`. From `get_my_name`.
    /// C distinguishes "tinc cannot run without a valid Name" — same
    /// message for missing-Name and bad-Name (`fsck.c:648`).
    NoName,
    /// `read_server_config` or `read_host_config` failed *after*
    /// `tinc.conf` was confirmed readable. Parse error in `conf.d/`,
    /// hosts file unreadable, etc. C: `if(!success)` at `fsck.c:664`.
    /// The `String` is `tinc-conf`'s `ReadError` Display — already
    /// includes the path and line.
    ConfigReadFailed(String),
    /// `ed25519_key.priv` (or `Ed25519PrivateKeyFile`) doesn't exist
    /// or PEM-parse failed. C: `if(!ec_priv)` at `fsck.c:576`. C
    /// doesn't distinguish missing-file from bad-PEM at the fsck
    /// level (both are "no private key found"); neither do we.
    NoPrivateKey { path: PathBuf },

    // ─── Keypair coherence
    /// `hosts/NAME` has neither `Ed25519PublicKey =` nor a PEM block.
    /// C: `fsck.c:423` "No (usable) public Ed25519 key found." Fixable.
    NoPublicKey { host_file: PathBuf },
    /// Priv-derived pubkey ≠ `hosts/NAME`'s pubkey. `fsck.c:406`.
    /// The most likely real-world cause: `tinc generate-ed25519-keys`
    /// ran but the user manually restored an old `hosts/NAME` from
    /// backup. Or copied a `hosts/NAME` from another node. Fixable.
    KeyMismatch { host_file: PathBuf },
    /// `hosts/NAME` exists but `access(R_OK)` failed. `fsck.c:541`.
    /// Warning only — keypair check still tries (might succeed via
    /// `Ed25519PublicKeyFile` pointing elsewhere, theoretically).
    HostFileUnreadable { host_file: PathBuf },

    // ─── File modes (Unix only)
    /// Private key file has mode `& 077 != 0` — group/other readable.
    /// `fsck.c:214`. Fixable iff `uid_match` (you can't chmod a file
    /// you don't own without root).
    UnsafeKeyMode {
        path: PathBuf,
        mode: u32,
        uid_match: bool,
    },

    // ─── Scripts
    /// `*-up`/`*-down` in confbase that isn't `tinc-`/`host-`/
    /// `subnet-`. `fsck.c:474`. Not fixable — fsck doesn't know what
    /// you intended. The C prints an explanation once (the `static
    /// bool explained` trick); we print it every time (simpler; the
    /// explanation is two lines, and you rarely have >1 unknown
    /// script).
    UnknownScript { path: PathBuf },
    /// Script exists but `access(R_OK | X_OK)` failed with `EACCES`.
    /// `fsck.c:437`. Fixable (`chmod 0755`).
    ScriptNotExecutable { path: PathBuf },
    /// Script `access` failed with a *non-EACCES* error. `fsck.c:432`.
    /// Probably ENOENT race (file deleted between `readdir` and
    /// `access`) or filesystem weirdness. Not fixable; the C just
    /// prints and moves on.
    ScriptAccessError { path: PathBuf, err: String },
    /// `opendir(confbase)` or `opendir(hosts/)` failed. `fsck.c:453`,
    /// `fsck.c:500`. The dir-level error; the script checks inside
    /// can't run. Contributes to `!ok` (`return false` in C).
    DirUnreadable { path: PathBuf, err: String },

    // ─── Per-variable validity
    /// `VAR_OBSOLETE` flag set. `fsck.c:170`. The four known: `Graph
    /// DumpFile`, `PrivateKey`, `PublicKey`, `PublicKeyFile`. Not
    /// fixable — fsck doesn't delete config lines.
    ObsoleteVar { name: String, source: Source },
    /// Non-`VAR_SERVER` var in `tinc.conf` (or `conf.d/`). `fsck.c:
    /// 175`. Probably `Port = 655` in `tinc.conf` — should be in
    /// `hosts/NAME`. The most common fsck warning in the wild.
    HostVarInServer { name: String, source: Source },
    /// Non-`VAR_HOST` var in `hosts/*`. `fsck.c:180`.
    ServerVarInHost { name: String, source: Source },
    /// Non-`VAR_MULTIPLE` var appears more than once. `fsck.c:185`.
    /// **The only place that surfaces silent-first-wins.** The
    /// `Config::lookup().next()` pattern means a second `Port = 999`
    /// is invisibly ignored — fsck is the canary.
    ///
    /// `where_` is `"tinc.conf"` for the server check or the node
    /// name for a host check. NOT a path — the C prints `nodename ?
    /// nodename : "tinc.conf"` (`fsck.c:188`), no directory. The
    /// duplicate spans the whole file so there's no single line
    /// number to print.
    DuplicateVar { name: String, where_: String },

    // ─── Fix results
    /// `chmod` succeeded. C: `fsck.c:223`, `fsck.c:441`.
    FixedMode { path: PathBuf },
    /// `disable_old_keys` + append-PEM-pubkey succeeded. `fsck.c:289`.
    FixedPublicKey { path: PathBuf },
    /// Tried to fix; the syscall failed. `fsck.c:221`, `:281`, etc.
    /// Carries the `io::Error` Display, not the structured error —
    /// it's terminal, nobody pattern-matches on *which* errno.
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
    /// Fix-result messages. C prints these without a prefix.
    Info,
}

impl Finding {
    /// `ERROR:` / `WARNING:` / (nothing) prefix. Matches C phrasing.
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

    /// Suggestion message for the findings that have one. C does
    /// `print_tinc_cmd(...)` after certain `fprintf`s — "here's the
    /// command to fix this manually". `cmd_prefix` is the `tinc -c
    /// /path` part the binary formats.
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

/// The C messages. Phrasing preserved for the same reason as
/// `CmdError::Display` — users grep error strings, forum posts
/// reference them. Minor deviations noted inline.
impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Finding as F;
        match self {
            // C `fsck.c:235` prints the strerror; the suggestion
            // (`print_tinc_cmd("init")`) is separate. We carry the
            // suggestion in `suggestion()`.
            F::TincConfMissing => {
                write!(f, "cannot read tinc.conf: No such file or directory")
            }
            F::TincConfDenied { running_as_root } => {
                if *running_as_root {
                    // C `fsck.c:249`. tinc.conf is owned by someone
                    // else and you're root — check the path components.
                    write!(
                        f,
                        "cannot read tinc.conf: Permission denied. Check the permissions of each component of the path."
                    )
                } else {
                    // C `fsck.c:247`.
                    write!(
                        f,
                        "cannot read tinc.conf: Permission denied. You are currently not running tinc as root. Use sudo?"
                    )
                }
            }
            F::NoName => {
                // C `fsck.c:648` (same message twice; once in
                // `read_node_name`, once in `fsck()` — it
                // double-prints. We don't.)
                write!(f, "tinc cannot run without a valid Name.")
            }
            F::ConfigReadFailed(e) => {
                // tinc-conf's `ReadError` Display already includes
                // the path. C just propagates `read_server_config`'s
                // own logger() call.
                write!(f, "{e}")
            }
            F::NoPrivateKey { path } => {
                // C `fsck.c:578`: `print_new_keys_cmd(KEY_ED25519,
                // "ERROR: No Ed25519 private key found.")`. The path
                // is added — C doesn't print it (it's implied), but
                // it's free here and the user might have set
                // `Ed25519PrivateKeyFile` to something surprising.
                write!(f, "No Ed25519 private key found at {}.", path.display())
            }
            F::NoPublicKey { host_file } => {
                // C `fsck.c:423`. Path added (same reasoning).
                write!(
                    f,
                    "No (usable) public Ed25519 key found in {}.",
                    host_file.display()
                )
            }
            F::KeyMismatch { host_file } => {
                // C `fsck.c:406`. Path added.
                write!(
                    f,
                    "public and private Ed25519 keys do not match. Public key in {} does not correspond to the private key.",
                    host_file.display()
                )
            }
            F::HostFileUnreadable { host_file } => {
                // C `fsck.c:542`.
                write!(f, "cannot read {}", host_file.display())
            }
            F::UnsafeKeyMode {
                path,
                mode,
                uid_match,
            } => {
                // C `fsck.c:215`. The mode is added — C doesn't show
                // it but `0640` vs `0644` tells you if it's group-
                // read or world-read at a glance. C `fsck.c:218`
                // appends the uid line conditionally; we inline.
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
                // C `fsck.c:477` plus the explanation (`fsck.c:480-
                // 483`). C uses `static bool explained` to print the
                // explanation once. We always print it — two lines,
                // and >1 unknown script is rare.
                write!(
                    f,
                    "Unknown script {} found. The only scripts in the configuration directory executed by tinc are: tinc-up, tinc-down, host-up, host-down, subnet-up, subnet-down.",
                    path.display()
                )
            }
            F::ScriptNotExecutable { path } => {
                // C `fsck.c:437`. C prints the strerror; for EACCES
                // that's "Permission denied" which is implied by
                // "cannot execute". Dropped for terseness.
                write!(f, "cannot read and execute {}", path.display())
            }
            F::ScriptAccessError { path, err } => {
                // C `fsck.c:433`. The non-EACCES path.
                write!(f, "cannot access {}: {err}", path.display())
            }
            F::DirUnreadable { path, err } => {
                // C `fsck.c:454`, `:500`.
                write!(f, "cannot read directory {}: {err}", path.display())
            }
            F::ObsoleteVar { name, source } => {
                // C `fsck.c:170`: "obsolete variable %s in %s line
                // %d". Our `Source` Display is "on line N while
                // reading config file PATH" — slightly more verbose,
                // same information.
                write!(f, "obsolete variable {name} {source}")
            }
            F::HostVarInServer { name, source } => {
                // C `fsck.c:176`. Note the trailing space in the C
                // format string ("%s line %d \n") — typo, dropped.
                write!(f, "host variable {name} found in server config {source}")
            }
            F::ServerVarInHost { name, source } => {
                // C `fsck.c:181`. Same trailing-space typo.
                write!(f, "server variable {name} found in host config {source}")
            }
            F::DuplicateVar { name, where_ } => {
                // C `fsck.c:188`. `where_` matches C's `nodename ?
                // nodename : "tinc.conf"` — a name, not a path.
                write!(f, "multiple instances of variable {name} in {where_}")
            }
            F::FixedMode { path } => {
                // C `fsck.c:223`. Past tense, no severity prefix.
                write!(f, "Fixed permissions of {}.", path.display())
            }
            F::FixedPublicKey { path } => {
                // C `fsck.c:289`.
                write!(f, "Wrote Ed25519 public key to {}.", path.display())
            }
            F::FixFailed { path, err } => {
                // Covers C `fsck.c:221`, `:281`, `:291`. Generic
                // because the path tells you what we were trying.
                write!(f, "could not fix {}: {err}", path.display())
            }
        }
    }
}

// Report

/// Everything fsck found, plus the bottom-line exit code.
#[derive(Debug)]
pub struct Report {
    /// In scan order. The order is roughly: tinc.conf existence →
    /// keypair → key mode → scripts → variables. C order (`fsck.c:
    /// fsck()`).
    pub findings: Vec<Finding>,
    /// `true` ↔ `EXIT_SUCCESS`. The C computes this as `success &
    /// check_scripts_and_configs()` — bitwise AND, no short circuit.
    /// We compute it the same way: each phase contributes a `bool`,
    /// final result is the AND. Warnings don't affect it; only the
    /// fatal checks (no tinc.conf, no priv key, unfixed mismatch).
    pub ok: bool,
}

// The scan

/// `fsck()` — `fsck.c:640-679`.
///
/// `force` is `--force`: apply fixes (chmod, rewrite pubkey) instead
/// of just warning. C also has interactive `y/n` prompts when `tty`;
/// we don't (see module doc).
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
    // C: `read_node_name()` (`fsck.c:230`). The `access(R_OK)` check
    // distinguishes ENOENT (suggest `tinc init`) from EACCES (suggest
    // `sudo`). We check via metadata — `access(2)` checks effective
    // UID, `metadata` doesn't, but for the common cases (file doesn't
    // exist / you can't read it) the difference is academic.
    let tinc_conf = paths.tinc_conf();
    let Ok(name) = get_my_name(paths) else {
        // get_my_name already wraps the error; we re-probe to
        // distinguish ENOENT from EACCES from no-Name. The C does
        // this with `access` + `errno` (`fsck.c:230-251`).
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
        // C `fsck.c:649`: early return. The remaining checks
        // (keypair, scripts, variables) all need either a name or
        // a confbase that we now know doesn't exist. C returns
        // EXIT_FAILURE here.
        return Ok(Report {
            findings,
            ok: false,
        });
    };

    // ─── Phase 1: read full config tree
    // C `fsck.c:660-661`: `read_server_config(&config) &&
    // read_host_config(&config, name, true)`. The `&&` short-circuits
    // — if server config fails, host isn't read. We do the same.
    //
    // `read_host_config` is `parse_file(hosts/NAME)` + merge — see
    // `tinc-conf::read_server_config` doc for why it's not a function.
    let host_file = paths.host_file(&name);
    let config_result = read_server_config(&paths.confbase).and_then(|mut cfg| {
        let host_entries = tinc_conf::parse_file(&host_file)?;
        cfg.merge(host_entries);
        Ok(cfg)
    });

    // Track keypair-phase success separately. C: `bool success`.
    let keypair_ok = match &config_result {
        Ok(cfg) => {
            // ─── Phase 2: keypair check
            // C `fsck.c:666`: `if(success) success = check_keypairs`.
            check_keypairs(paths, cfg, &host_file, force, &mut findings)
        }
        Err(e) => {
            findings.push(Finding::ConfigReadFailed(e.to_string()));
            false
        }
    };

    // ─── Phase 3+4: scripts + variables
    // C `fsck.c:672`: `success = success & check_scripts_and_configs()`.
    // **Bitwise `&`, not `&&`** — the comment at `fsck.c:670` says
    // "this check does not require working configuration, so run it
    // always". Even if Phase 2 failed, we still want script/variable
    // diagnostics. We replicate: scripts always run; variables run
    // unless the config-read itself failed (can't check vars in a
    // tree we couldn't build).
    let scripts_ok = check_scripts(paths, force, &mut findings);

    // Variable check. C runs `check_conffile(NULL, true)` for the
    // server tree, then `check_conffile(name, false)` for each
    // `hosts/*`. Each call re-parses the config (`read_server_config`
    // again) — wasteful but harmless. We re-read too; the alternative
    // (separating the merged-for-keypair tree back into its source
    // files) is worse.
    check_variables(paths, &mut findings);

    Ok(Report {
        findings,
        // The `&` is the C `fsck.c:672` semantics. `scripts_ok`
        // contributes; variable warnings never do (they're warnings
        // — `check_conffile` is `void` in C, returns nothing).
        ok: keypair_ok & scripts_ok,
    })
}

// Phase 2: Keypair coherence

/// `check_keypairs` (`fsck.c:563`) + `check_public_keys` (`fsck.c:
/// 530`) + `check_ec_pubkey` (`fsck.c:410`) + `test_ec_keypair`
/// (`fsck.c:380`). Collapsed because under `DISABLE_LEGACY` the three
/// inner functions are each called from exactly one place and the
/// indirection is just `#ifdef` scaffolding.
///
/// Returns the C `success` bool. `false` only for unfixable failures:
/// no private key, or mismatch + `!force`. With `force`, mismatch is
/// fixed and returns `true`.
fn check_keypairs(
    paths: &Paths,
    cfg: &Config,
    host_file: &Path,
    force: bool,
    findings: &mut Vec<Finding>,
) -> bool {
    // ─── Load private key
    // C `keys.c:108`: check `Ed25519PrivateKeyFile` config first,
    // fall back to `<confbase>/ed25519_key.priv`. fsck respects this;
    // genkey/sign currently don't (see module doc).
    //
    // `lookup` is case-insensitive (`vars.rs::lookup` is too); the
    // canonical case is `Ed25519PrivateKeyFile` per the table.
    let priv_path: PathBuf = cfg
        .lookup("Ed25519PrivateKeyFile")
        .next()
        .map_or_else(|| paths.ed25519_private(), |e| PathBuf::from(e.get_str()));

    let Ok(sk) = keypair::read_private(&priv_path) else {
        // C `fsck.c:576-579`: `if(!ec_priv) { print; return
        // false; }`. The `read_ecdsa_private_key` it calls also
        // logs via `logger()` (`keys.c:121`), so C double-prints.
        // We single-print. C doesn't distinguish ENOENT from bad
        // PEM at the fsck level (both produce `ec_priv == NULL`);
        // neither do we.
        findings.push(Finding::NoPrivateKey { path: priv_path });
        return false;
    };

    // ─── Check private key file mode
    // C `fsck.c:568`: `if(priv_keyfile) check_key_file_mode`. The
    // `if` is because `read_ecdsa_private_key`'s out-param can be
    // NULL on failure — but we already returned above on failure, so
    // unconditionally check here. Unix-only; the C has a no-op stub
    // for Windows (`fsck.c:201`).
    #[cfg(unix)]
    check_key_mode(&priv_path, force, findings);

    // ─── Host file readability
    // C `fsck.c:541`: `if(access(host_file, R_OK))` — warn but
    // continue. The pubkey load below might still succeed via
    // `Ed25519PublicKeyFile` (different path) or might fail more
    // specifically. The warning is "heads up, your hosts/NAME is
    // weird". `metadata()` over `access()` for the same reason as
    // Phase 0.
    if fs::File::open(host_file).is_err() {
        findings.push(Finding::HostFileUnreadable {
            host_file: host_file.to_owned(),
        });
        // C continues. We do too — `load_ec_pubkey` will hit the
        // same wall and produce `NoPublicKey`, which is the
        // *actionable* finding. This is just early-warning noise,
        // kept for C parity.
    }

    // ─── Load public key from config tree + host file
    // C `keys.c:165` `read_ecdsa_public_key`. Three-step lookup:
    //   1. `Ed25519PublicKey = <b64>` config entry
    //   2. `Ed25519PublicKeyFile = <path>` → PEM-read that path
    //   3. PEM-read `hosts/NAME` directly (default for #2)
    let pubkey = load_ec_pubkey(cfg, host_file);

    // ─── Coherence check
    // C `fsck.c:410-425` `check_ec_pubkey`. Four-way matrix on
    // (priv?, pub?). priv=None already returned above. Remaining:
    //
    //   pub=Some, match  → ok
    //   pub=Some, !match → KeyMismatch, fixable
    //   pub=None         → NoPublicKey, fixable
    //
    // C does the comparison via `b64encode(priv->public)` vs
    // `b64encode(pub)` strcmp (`fsck.c:398`). We compare bytes
    // directly — no need to round-trip through b64. (The b64 in C is
    // because `ecdsa_t` is opaque and `ecdsa_get_base64_public_key`
    // is the only "give me the pubkey" accessor. Our `SigningKey`
    // has `public_key()` returning bytes.)
    //
    // The "private key does not work" branch (`fsck.c:384`): see
    // module doc — it's dead code, `ecdsa_get_base64_public_key`
    // can't fail. Dropped.
    let priv_derived: &[u8; PUBLIC_LEN] = sk.public_key();

    match pubkey {
        Some(pk) if pk == *priv_derived => {
            // The happy path. C: `if(match) return true` (`fsck.c:
            // 402`). No finding, no message. fsck on a clean `tinc
            // init` lands here.
            true
        }
        Some(_) => {
            findings.push(Finding::KeyMismatch {
                host_file: host_file.to_owned(),
            });
            // C `fsck.c:407`: `return ask_fix_ec_public_key(...)`.
            // With force, fix and return its result. Without, the
            // C `ask_fix()` returns `false` (no prompt, no force),
            // and `ask_fix_ec_public_key` then returns `true`
            // (`fsck.c:271`) — which is *weird*: "I found a mismatch
            // and you didn't fix it, so... success?". But that IS
            // what the C does. The reason: `ask_fix_ec_public_key`
            // returning false would cascade to `fsck()` returning
            // failure, but the C apparently considers "user declined
            // to fix" as "user's choice, not fsck's failure". We
            // tighten: `!force` → `false`. A mismatch you didn't fix
            // is a failed fsck. The user said `--force` to fix; they
            // said nothing to fail; the C's "decline = success" is a
            // bug we don't carry.
            if force {
                fix_public_key(host_file, priv_derived, findings)
            } else {
                false
            }
        }
        None => {
            findings.push(Finding::NoPublicKey {
                host_file: host_file.to_owned(),
            });
            // C `fsck.c:424`: same `ask_fix_ec_public_key` call.
            // Same tightening.
            if force {
                fix_public_key(host_file, priv_derived, findings)
            } else {
                false
            }
        }
    }
}

/// `read_ecdsa_public_key` (`keys.c:165`). The three-step lookup.
///
/// Returns `None` for any failure — file missing, bad b64, wrong
/// length, no PEM block. fsck doesn't distinguish these (all are "no
/// usable public key"). The structured `LoadError` from
/// `keypair::read_public` would be nice for diagnostics, but C
/// doesn't expose it and adding it now is scope creep.
///
/// `cfg` is the *merged* tree (server + host). `Ed25519PublicKey` is
/// `VAR_HOST`-only (per the table) so it'll only ever come from the
/// host file in practice, but the lookup doesn't care.
fn load_ec_pubkey(cfg: &Config, default_host_file: &Path) -> Option<[u8; PUBLIC_LEN]> {
    // ─── Step 1: Ed25519PublicKey = <b64>
    // C `keys.c:179`: `if(get_config_string(lookup_config(...)))`.
    // The b64 decode + length check is `ecdsa_set_base64_public_key`
    // (`ed25519/ecdsa.c:42`); on bad b64 it returns NULL and the C
    // *doesn't* fall through to PEM — it returns NULL from the whole
    // function. We do the same: bad b64 in the config is `None`, not
    // "try PEM". The reasoning: a malformed `Ed25519PublicKey =`
    // line is a config bug, not a "let me look elsewhere" situation.
    if let Some(entry) = cfg.lookup("Ed25519PublicKey").next() {
        let raw = b64::decode(entry.get_str())?;
        return raw.try_into().ok();
    }

    // ─── Step 2+3: Ed25519PublicKeyFile or default → PEM read
    // C `keys.c:187-199`. The default (when `Ed25519PublicKeyFile`
    // unset) is `hosts/NAME`, which is *also* the file we'd parse for
    // the config-line form. So step 1 and step 3 read the same file.
    // The reason for both: `tinc init` writes config-line, but `fsck
    // --force` writes PEM (see module doc). And legacy configs from
    // pre-1.1 used PEM. Both forms exist in the wild.
    let pem_path: PathBuf = cfg.lookup("Ed25519PublicKeyFile").next().map_or_else(
        || default_host_file.to_owned(),
        |e| PathBuf::from(e.get_str()),
    );

    // `read_public` does open + read_pem + length check. Any failure
    // → None. (The C distinguishes ENOENT from PEM-parse-failure for
    // logging — `keys.c:204` `if(!ecdsa && errno != ENOENT)` — but
    // fsck doesn't see that distinction.)
    keypair::read_public(&pem_path).ok()
}

/// `ask_fix_ec_public_key` (`fsck.c:269`), minus the `ask_fix()`
/// gate (caller already checked `force`).
///
/// `disable_old_keys` to comment out whatever was there, then append
/// a PEM block with the priv-derived public key. Returns `true` iff
/// both succeeded. Records `FixedPublicKey` or `FixFailed`.
fn fix_public_key(
    host_file: &Path,
    pubkey: &[u8; PUBLIC_LEN],
    findings: &mut Vec<Finding>,
) -> bool {
    // ─── disable_old_keys
    // C `fsck.c:274`: `if(!disable_old_keys(fname, "public Ed25519
    // key")) return false`. Our `disable_old_keys` is `Result<bool>`
    // — `Err` is the C `false` (write/rename failed), both `Ok(true)`
    // and `Ok(false)` are the C `true` ("safe to append": either
    // nothing matched or it was successfully commented). The bool is
    // genkey's "did I touch anything", which fsck doesn't care about.
    if let Err(e) = disable_old_keys(host_file) {
        findings.push(Finding::FixFailed {
            path: host_file.to_owned(),
            err: e.to_string(),
        });
        return false;
    }

    // ─── Append PEM block
    // C `fsck.c:278-294`: `fopen("a")` + `ecdsa_write_pem_public_key`.
    // The C uses `fopen` directly (not `fopenmask`) — append mode,
    // existing perms preserved, no chmod. We use `OpenOptions::
    // append`. genkey's `open_append` would set a create-mode but
    // hosts files are 0644-ish from `tinc init` and we're appending
    // to an existing one; the create-mode is moot.
    //
    // The PEM-not-config-line choice: see module doc.
    let result = (|| -> std::io::Result<()> {
        let f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(host_file)?;
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::pem::write_pem(&mut w, TY_PUBLIC, pubkey)?;
        w.flush()
    })();

    match result {
        Ok(()) => {
            findings.push(Finding::FixedPublicKey {
                path: host_file.to_owned(),
            });
            true
        }
        Err(e) => {
            findings.push(Finding::FixFailed {
                path: host_file.to_owned(),
                err: e.to_string(),
            });
            false
        }
    }
}

// Phase 3: Key file mode

/// `check_key_file_mode` (`fsck.c:205`). Unix-only — the C has a
/// no-op stub for Windows.
///
/// `& 077` check: any bits in group/other. `0600` passes, `0640`
/// doesn't. C also checks `st_uid != getuid()` to decide whether to
/// offer the fix — you can't `chmod` a file you don't own (without
/// root). We push a `Finding` either way; the `uid_match` field
/// gates the fix.
#[cfg(unix)]
fn check_key_mode(path: &Path, force: bool, findings: &mut Vec<Finding>) {
    use std::os::unix::fs::MetadataExt; // for st_uid

    // C `fsck.c:209`: `if(stat(fname, &st))` → ERROR + return. We
    // already successfully opened this file (in `read_private`), so
    // metadata failing here would be a TOCTOU race. Just skip — the
    // `read_private` call is the real existence check.
    let Ok(meta) = fs::metadata(path) else {
        return;
    };

    let mode = meta.permissions().mode();
    // C `fsck.c:214`: `if(st.st_mode & 077)`. clippy suggests
    // `mode.trailing_zeros() >= 6` here, which is technically
    // equivalent but obfuscates the intent: this is a Unix
    // permission-bit mask, not a power-of-2 check. The C is
    // `& 077`; the port is `& 0o077`. Reads as what it is.
    #[allow(clippy::verbose_bit_mask)]
    if mode & 0o077 == 0 {
        return; // clean
    }

    // C `fsck.c:217`: `if(st.st_uid != uid)`. nix has `Uid` but
    // `MetadataExt::uid()` returns `u32` directly; compare against
    // `nix::unistd::getuid().as_raw()` — both `u32`.
    let uid_match = meta.uid() == nix::unistd::getuid().as_raw();

    findings.push(Finding::UnsafeKeyMode {
        path: path.to_owned(),
        mode,
        uid_match,
    });

    if !force || !uid_match {
        // C `fsck.c:219`: `else if(ask_fix())` — the `else` means
        // uid mismatch skips the fix. Same here.
        return;
    }

    // C `fsck.c:220`: `chmod(fname, st.st_mode & ~077u)`. Mask off
    // group/other, preserve owner bits + sticky/suid (the `& ~077u`
    // is `& 0o7700` effectively, modulo the type bits).
    let fixed = fs::Permissions::from_mode(mode & !0o077);
    match fs::set_permissions(path, fixed) {
        Ok(()) => findings.push(Finding::FixedMode {
            path: path.to_owned(),
        }),
        Err(e) => findings.push(Finding::FixFailed {
            path: path.to_owned(),
            err: e.to_string(),
        }),
    }
}

// Phase 4: Scripts

/// `check_scripts_and_configs` (`fsck.c:624`) minus the
/// `check_config_variables` half (that's `check_variables` below).
/// Returns the `bool` that contributes to `Report::ok` — `false`
/// only if `confbase` or `hosts/` couldn't be `opendir`'d.
fn check_scripts(paths: &Paths, force: bool, findings: &mut Vec<Finding>) -> bool {
    let confbase_ok = scan_scripts_in(&paths.confbase, ScriptDir::Confbase, force, findings);
    let hosts_ok = scan_scripts_in(&paths.hosts_dir(), ScriptDir::Hosts, force, findings);
    // C: short-circuit `&&` (`fsck.c:626-634`). Confbase fail skips
    // hosts scan. We don't short-circuit — more diagnostics, and
    // the directory-read errors are independent. Tightening.
    confbase_ok & hosts_ok
}

/// Distinguishes the two script directories. They differ in *one*
/// way: confbase validates the prefix (`tinc`/`host`/`subnet`),
/// hosts/ doesn't (any `*-up`/`*-down` is a per-host script).
#[derive(Clone, Copy)]
enum ScriptDir {
    /// `<confbase>/`. Prefix-validated.
    Confbase,
    /// `<confbase>/hosts/`. Any prefix is a node name.
    Hosts,
}

/// `check_script_confdir` (`fsck.c:448`) + `check_script_hostdir`
/// (`fsck.c:495`). They're 90% the same loop; the 10% is prefix
/// validation, gated on `kind`.
///
/// C does `strtailcmp(d_name, "-up") && strtailcmp(d_name, "-down")`
/// — the `&&` is because `strtailcmp` returns 0 on match (it's
/// `memcmp`-style). Reads as "if NOT-ends-with-up AND NOT-ends-with-
/// down, skip". We `.ends_with()` directly.
fn scan_scripts_in(dir: &Path, kind: ScriptDir, force: bool, findings: &mut Vec<Finding>) -> bool {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            // C `fsck.c:453`: `fprintf; return false`. The dir-level
            // failure contributes to `!ok`.
            findings.push(Finding::DirUnreadable {
                path: dir.to_owned(),
                err: e.to_string(),
            });
            return false;
        }
    };

    for ent in rd {
        // readdir entry error. C: invisible (NULL = error OR eof).
        // We: skip the broken entry, keep scanning. fsck on a
        // directory with one bad entry should still check the others.
        let Ok(ent) = ent else { continue };
        let fname = ent.file_name();
        let Some(fname) = fname.to_str() else {
            continue; // non-UTF-8 filenames: not scripts (scripts have
            // ASCII names by construction)
        };

        // C `fsck.c:461`: `if(strtailcmp(..., "-up") && strtailcmp(
        // ..., "-down")) continue`. Suffix check.
        let prefix = if let Some(p) = fname.strip_suffix("-up") {
            p
        } else if let Some(p) = fname.strip_suffix("-down") {
            p
        } else {
            continue;
        };

        // C `fsck.c:466-470`: `strrchr(fname, '-'); *dash = 0` —
        // strips the *last* `-`. Our `strip_suffix` strips the whole
        // suffix. They differ on `foo-bar-up`: C gets `foo-bar`, we
        // get `foo-bar`. They agree (`-up` is the last `-`). On
        // `foo-up-up`: C gets `foo-up`, we get `foo-up`. Still agree.
        // The cases where `strrchr('-')` ≠ `strip_suffix("-up")` are
        // when there's a `-` after `-up` — but then `strtailcmp`
        // already failed and we `continue`d. Equivalent.
        //
        // The empty-prefix case: a file literally named `-up`. C:
        // `strrchr` finds the `-`, sets `*dash = 0`, prefix is `""`.
        // Then `strcmp("", "tinc")` is nonzero → unknown script. We:
        // `strip_suffix` returns `""`, same outcome.

        let full_path = dir.join(fname);

        // ─── Prefix validation (confbase only)
        // C `fsck.c:474-485`. hosts/ skips this — `check_script_host
        // dir` does the suffix-strip-then-ignore dance (see module
        // doc), accepting any prefix as a node name.
        if matches!(kind, ScriptDir::Confbase) && !matches!(prefix, "tinc" | "host" | "subnet") {
            findings.push(Finding::UnknownScript { path: full_path });
            // C: `continue`. Unknown scripts aren't checked for
            // executability — they shouldn't run, so who cares.
            continue;
        }

        // ─── Executability check
        // C `fsck.c:428` `check_config_mode`: `access(fname, R_OK |
        // X_OK)`. We don't have `access(2)` directly without the
        // `nix` `unistd` feature, but we can check via metadata
        // mode bits — for the *owner*. `access` checks effective UID
        // against the bits, which is more correct (you might own a
        // 0755 file as non-owner and still be able to exec it via
        // the other-exec bit). But: scripts created by `tinc init`
        // are owned by you (you ran init); the case where fsck cares
        // is "tinc-up exists but isn't +x", and that's an owner-bit
        // check 99% of the time.
        //
        // We use mode bits. The remaining 1% (you `chown`'d your
        // tinc-up to someone else for... reasons?) gets a false
        // positive. Acceptable. The `nix` access feature is one
        // line away if it ever matters.
        check_script_exec(&full_path, force, findings);
    }

    true
}

/// `check_config_mode` (`fsck.c:427`). The `access(R_OK | X_OK)` +
/// optional `chmod 0755` fix.
fn check_script_exec(path: &Path, force: bool, findings: &mut Vec<Finding>) {
    #[cfg(unix)]
    {
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                // C `fsck.c:432`: `if(errno != EACCES) { fprintf
                // ERROR; return false; }`. The `return false` is from
                // `check_config_mode`, not from the whole fsck — and
                // the caller (`check_script_confdir`) ignores the
                // return value. So it's effectively just a print.
                // Weird C; we just push the finding.
                findings.push(Finding::ScriptAccessError {
                    path: path.to_owned(),
                    err: e.to_string(),
                });
                return;
            }
        };

        let mode = meta.permissions().mode();
        // `access(R_OK | X_OK)` for the file owner: `S_IRUSR | S_IXUSR`
        // = `0o500`. We check both bits set. (C `access` also checks
        // group/other if you're not the owner; see `scan_scripts_in`
        // comment for why we punt on that.)
        if mode & 0o500 == 0o500 {
            return; // executable by owner; good
        }

        findings.push(Finding::ScriptNotExecutable {
            path: path.to_owned(),
        });

        if !force {
            return;
        }

        // C `fsck.c:440`: `chmod(fname, 0755)`. Hard-coded 0755, not
        // `mode | 0o111` — fsck normalizes to "the mode `tinc init`
        // would've used". Preserves the convention.
        match fs::set_permissions(path, fs::Permissions::from_mode(0o755)) {
            Ok(()) => findings.push(Finding::FixedMode {
                path: path.to_owned(),
            }),
            Err(e) => findings.push(Finding::FixFailed {
                path: path.to_owned(),
                err: e.to_string(),
            }),
        }
    }
    #[cfg(not(unix))]
    {
        // Windows: no execute bit. C uses `_waccess` which checks
        // existence + readability, no executability. fsck-on-Windows
        // doesn't really do this check.
        let _ = (path, force, findings);
    }
}

// Phase 5: Variables

/// `check_config_variables` (`fsck.c:607`). Scan server config + each
/// `hosts/*` for obsolete/wrong-file/duplicate vars. Warnings only;
/// returns nothing (C function is `void`).
///
/// C re-parses every file (`check_conffile` calls `read_server_config`
/// fresh, `fsck.c:129`). Wasteful — we already parsed them in Phase 1
/// — but the merged tree from Phase 1 has lost the per-file separation
/// (server vs each-host). C's re-parse-per-check is the simplest way
/// to get that back. We do the same. The waste is one extra pass over
/// ~100 lines of config; not worth a refactor.
fn check_variables(paths: &Paths, findings: &mut Vec<Finding>) {
    // ─── Server config
    // C `fsck.c:608`: `check_conffile(NULL, true)`. NULL nodename →
    // server.
    if let Ok(cfg) = read_server_config(&paths.confbase) {
        // `where_` for the duplicate message: C uses `nodename ?
        // nodename : "tinc.conf"` (`fsck.c:188`). Literal string,
        // not a path. (Slightly wrong if conf.d/*.conf is the source
        // of the duplicate — both C and we say "tinc.conf" anyway.
        // C bug; carried.)
        check_conf(&cfg, true, "tinc.conf", findings);
    }
    // C `fsck.c:129-135`: `if(!read) { return; }`. Read failure on
    // server config → skip the var check. We do the same (the `if
    // let Ok` already does it). A `ConfigReadFailed` was already
    // pushed in Phase 1 if this is the case.

    // ─── Each host file
    // C `fsck.c:612-618`: `opendir(hosts); for each ent: if check_id
    // (d_name) check_conffile(d_name, false)`. The `check_id` filter
    // skips `.`, `..`, and any `hosts/*` that isn't a valid node
    // name (which would be junk — `tinc init` only creates valid-
    // named files).
    let Ok(rd) = fs::read_dir(paths.hosts_dir()) else {
        // C `fsck.c:611`: `if(dir)` — silent skip on opendir failure.
        // The hosts/ dir was already checked in Phase 4; the
        // `DirUnreadable` finding is there. Don't double-report.
        return;
    };
    for ent in rd {
        let Ok(ent) = ent else { continue };
        let fname = ent.file_name();
        let Some(node) = fname.to_str() else { continue };
        if !check_id(node) {
            continue;
        }

        // `read_host_config` = `parse_file(hosts/NODE)`. C `fsck.c:
        // 131`.
        let Ok(entries) = tinc_conf::parse_file(paths.host_file(node)) else {
            // C: `if(!read) return` from `check_conffile` — silent
            // skip per-file. (The host file might be unparseable;
            // that's a different fsck phase's job to catch. The C
            // doesn't catch it though — `read_host_config` failure
            // here is just silent. We follow.)
            continue;
        };
        let mut cfg = Config::new();
        cfg.merge(entries);
        check_conf(&cfg, false, node, findings);
    }
}

/// `check_conffile` (`fsck.c:122`). The four warnings: obsolete,
/// host-var-in-server, server-var-in-host, duplicate-non-multiple.
///
/// `is_server`: `true` for `tinc.conf`+`conf.d/`, `false` for a
/// `hosts/NODE` file. Determines which "wrong file" check applies.
///
/// `where_`: the C `nodename ? nodename : "tinc.conf"` string — what
/// to print in the duplicate message. NOT a path.
fn check_conf(cfg: &Config, is_server: bool, where_: &str, findings: &mut Vec<Finding>) {
    // ─── Per-entry pass: obsolete + wrong-file
    // C `fsck.c:154-183`. The `count[i]` array is `alloca`'d in C;
    // we use a `Vec` of the same length. Index = position in `VARS`
    // (which we preserved from C — see `vars.rs` module doc).
    //
    // `VARS.len()` is 74, asserted at compile time. `vec![0; 74]`
    // is fine. (C `alloca(74 * sizeof(int))` is also fine.)
    let mut count = vec![0u32; VARS.len()];

    for entry in cfg.entries() {
        // C `fsck.c:157-163`: linear scan of `variables[]`. We use
        // `lookup_var` (same scan, named). The C *also* loops to
        // find the index for `count[i]++` — we need the index too,
        // so we replicate the loop here rather than calling
        // `lookup_var`. (`.position()` gives us the index;
        // `lookup_var` doesn't.)
        let Some(idx) = VARS
            .iter()
            .position(|v| v.name.eq_ignore_ascii_case(&entry.variable))
        else {
            // C `fsck.c:164`: `if(var_type == 0) continue`. Unknown
            // var. NOT a warning — see module doc + vars.rs doc. The
            // C is silent; we're silent. TODO(feature): warn on
            // unknown vars. Not a port; a feature.
            continue;
        };
        count[idx] += 1;
        let flags = VARS[idx].flags;

        // C `fsck.c:169`: `if(var_type & VAR_OBSOLETE)`.
        if flags.contains(VarFlags::OBSOLETE) {
            findings.push(Finding::ObsoleteVar {
                name: entry.variable.clone(),
                source: entry.source.clone(),
            });
        }

        // C `fsck.c:174`: `if(server && !(var_type & VAR_SERVER))`.
        // A `VAR_HOST`-only var (like `Port`, `Subnet`, `Address`)
        // appearing in `tinc.conf`. The most common real-world fsck
        // warning — people put `Port = 655` in `tinc.conf` because
        // that's where you'd intuitively put it.
        if is_server && !flags.contains(VarFlags::SERVER) {
            findings.push(Finding::HostVarInServer {
                name: entry.variable.clone(),
                source: entry.source.clone(),
            });
        }

        // C `fsck.c:179`: `if(!server && !(var_type & VAR_HOST))`.
        // The mirror. Rarer — server-only vars are things like
        // `Device`, `Interface`, `BindToAddress`, which nobody
        // accidentally puts in `hosts/*`.
        if !is_server && !flags.contains(VarFlags::HOST) {
            findings.push(Finding::ServerVarInHost {
                name: entry.variable.clone(),
                source: entry.source.clone(),
            });
        }
    }

    // ─── Duplicate pass
    // C `fsck.c:185-190`. Second loop over `count[]`. Separate pass
    // because the duplicate warning is per-variable-NAME, not
    // per-entry — it doesn't have a single line number.
    for (idx, &n) in count.iter().enumerate() {
        if n > 1 && !VARS[idx].flags.contains(VarFlags::MULTIPLE) {
            findings.push(Finding::DuplicateVar {
                // Canonical case from the table, not whatever case
                // the user typed. C `fsck.c:188` does the same
                // (`variables[i].name`).
                name: VARS[idx].name.to_owned(),
                where_: where_.to_owned(),
            });
        }
    }
}

// Platform helpers

#[cfg(unix)]
fn is_root() -> bool {
    nix::unistd::getuid().is_root()
}

#[cfg(not(unix))]
fn is_root() -> bool {
    // Windows: no `getuid`. The C `getuid()` stub for Windows
    // (`fsck.c:197`) returns 0, which makes `is_root()` always true.
    // That changes which EACCES message prints — minor. We pick
    // false (the more cautious message). Doesn't matter much; the
    // Windows path is barely tested in the C either.
    false
}

// suppress unused-import on non-unix where lookup_var is only used
// implicitly via the position() loop
#[allow(unused_imports)]
use lookup_var as _;

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::PathsInput;

    /// Build a `Paths` rooted at a tempdir's child. The child doesn't
    /// exist yet — tests that need it call `tinc init` (via the
    /// helpers below) to create it.
    fn paths_at(dir: &tempfile::TempDir) -> (PathBuf, Paths) {
        let confbase = dir.path().join("vpn");
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase.clone()),
            ..Default::default()
        });
        (confbase, paths)
    }

    /// `tinc init NAME` via the function, not the binary. Creates
    /// the full dir tree + keys. Unit-test scope; the binary is for
    /// integration tests.
    fn init(paths: &Paths, name: &str) {
        crate::cmd::init::run(paths, name).unwrap();
    }

    /// Count findings matching a predicate. Shorter than the
    /// `iter().filter().count()` chain at every assert site.
    fn count<F: Fn(&Finding) -> bool>(report: &Report, f: F) -> usize {
        report.findings.iter().filter(|x| f(x)).count()
    }

    // Phase 0: tinc.conf existence

    /// Clean `tinc init` → fsck passes, zero findings. The contract
    /// test: `init` and `fsck` must agree on what "clean" means. If
    /// `init` ever starts writing something fsck warns about, this
    /// catches it.
    #[test]
    fn clean_init_passes() {
        let dir = tempfile::tempdir().unwrap();
        let (_, paths) = paths_at(&dir);
        init(&paths, "alice");

        let r = run(&paths, false).unwrap();
        assert!(r.ok, "clean init should pass: {:?}", r.findings);
        assert!(
            r.findings.is_empty(),
            "clean init should have zero findings: {:?}",
            r.findings
        );
    }

    /// No `tinc.conf` at all → `TincConfMissing`, fail. The
    /// suggestion mentions `init`.
    #[test]
    fn no_tincconf() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        fs::create_dir_all(&confbase).unwrap();
        // Dir exists but is empty.

        let r = run(&paths, false).unwrap();
        assert!(!r.ok);
        assert_eq!(count(&r, |f| matches!(f, Finding::TincConfMissing)), 1);
        // The suggestion text.
        let f = &r.findings[0];
        assert!(f.suggestion("tinc -c /x").unwrap().contains("init"));
    }

    /// `tinc.conf` exists but no `Name =` → `NoName`.
    #[test]
    fn no_name() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        fs::create_dir_all(&confbase).unwrap();
        // tinc.conf with stuff but no Name.
        fs::write(confbase.join("tinc.conf"), "Port = 655\n").unwrap();

        let r = run(&paths, false).unwrap();
        assert!(!r.ok);
        assert_eq!(count(&r, |f| matches!(f, Finding::NoName)), 1);
    }

    // Phase 2: Keypair

    /// `ed25519_key.priv` deleted → `NoPrivateKey`, fail. The
    /// suggestion mentions `generate-ed25519-keys`.
    #[test]
    fn no_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");
        fs::remove_file(confbase.join("ed25519_key.priv")).unwrap();

        let r = run(&paths, false).unwrap();
        assert!(!r.ok);
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::NoPrivateKey { .. }))
            .unwrap();
        assert!(
            f.suggestion("tinc -c /x")
                .unwrap()
                .contains("generate-ed25519-keys")
        );
        // Phase 4+5 still ran. The C `&` not `&&` (`fsck.c:672`).
        // No findings from them on a clean init, but the absence of
        // a panic proves we didn't short-circuit.
    }

    /// `Ed25519PrivateKeyFile` config respected. The default-location
    /// key is gone, but the config points elsewhere.
    ///
    /// This is the check that genkey/sign DON'T do (see module doc) —
    /// fsck has the config tree, they don't. Pinning fsck's behavior
    /// here so when we fix sign, this test is the reference.
    #[test]
    fn private_key_file_config() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // Move the private key elsewhere.
        let alt = confbase.join("my_key.pem");
        fs::rename(confbase.join("ed25519_key.priv"), &alt).unwrap();
        // Tell tinc.conf where it is. Append (init wrote `Name =`).
        let mut tc = fs::OpenOptions::new()
            .append(true)
            .open(confbase.join("tinc.conf"))
            .unwrap();
        writeln!(tc, "Ed25519PrivateKeyFile = {}", alt.display()).unwrap();

        let r = run(&paths, false).unwrap();
        assert!(r.ok, "should find the relocated key: {:?}", r.findings);
        assert_eq!(count(&r, |f| matches!(f, Finding::NoPrivateKey { .. })), 0);
    }

    /// `hosts/NAME` deleted entirely → `ConfigReadFailed`. Phase 1
    /// (`parse_file(hosts/NAME)`) fails before the keypair check can
    /// run. C: `read_host_config` returns false → `success = false`
    /// → `if(success) check_keypairs` skipped. Same here.
    ///
    /// (Initially I expected `NoPublicKey` here. Wrong: `NoPublicKey`
    /// is for "file exists but has no key", not "file is gone". The
    /// distinction matters because the suggestion differs — missing
    /// file is `tinc init`-level breakage, missing-key-in-file is
    /// a `--force` fix.)
    #[test]
    fn host_file_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");
        fs::remove_file(confbase.join("hosts/alice")).unwrap();

        let r = run(&paths, false).unwrap();
        assert!(!r.ok);
        // ConfigReadFailed, NOT NoPublicKey. Phase 1 failed.
        assert_eq!(count(&r, |f| matches!(f, Finding::ConfigReadFailed(_))), 1);
        assert_eq!(count(&r, |f| matches!(f, Finding::NoPublicKey { .. })), 0);
    }

    /// `hosts/NAME` exists but has no pubkey (just `Subnet =` etc.)
    /// → `NoPublicKey`, fail. THIS is the path where the keypair
    /// check runs and finds nothing. NOT fixable without `--force`.
    #[test]
    fn no_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");
        // Replace hosts/alice with config-only content. No pubkey,
        // no PEM block. `parse_file` succeeds (it's valid config),
        // `load_ec_pubkey` returns None.
        fs::write(confbase.join("hosts/alice"), "Subnet = 10.0.0.0/24\n").unwrap();

        let r = run(&paths, false).unwrap();
        assert!(!r.ok);
        assert_eq!(count(&r, |f| matches!(f, Finding::NoPublicKey { .. })), 1);
        // File IS readable (we just wrote it); no early-warning.
        assert_eq!(
            count(&r, |f| matches!(f, Finding::HostFileUnreadable { .. })),
            0
        );
        // No fix attempted.
        assert_eq!(
            count(&r, |f| matches!(f, Finding::FixedPublicKey { .. })),
            0
        );
    }

    /// `hosts/NAME` has the WRONG pubkey → `KeyMismatch`, fail.
    /// The most realistic broken-config case: somebody copied a
    /// `hosts/alice` from a different node.
    #[test]
    fn key_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // Overwrite hosts/alice with a different pubkey. We use a
        // freshly-generated one so it's a *valid* pubkey, just wrong.
        // (An invalid b64 would hit a different code path —
        // `load_ec_pubkey` returns None on bad b64.)
        let other = keypair::generate();
        let other_b64 = b64::encode(other.public_key());
        fs::write(
            confbase.join("hosts/alice"),
            format!("Ed25519PublicKey = {other_b64}\n"),
        )
        .unwrap();

        let r = run(&paths, false).unwrap();
        // The tightening (see check_keypairs comment): unfixed
        // mismatch is a *fail*, not a pass. C returns true here
        // (the "decline = success" weirdness). We don't.
        assert!(!r.ok);
        assert_eq!(count(&r, |f| matches!(f, Finding::KeyMismatch { .. })), 1);
    }

    /// `KeyMismatch` + `--force` → `FixedPublicKey`, pass. The
    /// hosts/alice file gets `disable_old_keys` + a fresh PEM block.
    /// **Contract test**: re-run fsck on the fixed file; it must pass.
    #[test]
    fn key_mismatch_force_fixes() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let other = keypair::generate();
        let other_b64 = b64::encode(other.public_key());
        fs::write(
            confbase.join("hosts/alice"),
            format!("Ed25519PublicKey = {other_b64}\n"),
        )
        .unwrap();

        // First fsck: --force.
        let r1 = run(&paths, true).unwrap();
        assert!(r1.ok, "--force should fix and pass: {:?}", r1.findings);
        assert_eq!(count(&r1, |f| matches!(f, Finding::KeyMismatch { .. })), 1);
        assert_eq!(
            count(&r1, |f| matches!(f, Finding::FixedPublicKey { .. })),
            1
        );

        // The file shape: old config-line is `#`-commented, new
        // PEM block appended. PEM-not-config-line per module doc.
        let host = fs::read_to_string(confbase.join("hosts/alice")).unwrap();
        assert!(host.starts_with("#Ed25519PublicKey ="));
        assert!(host.contains("-----BEGIN ED25519 PUBLIC KEY-----"));

        // Second fsck: no force. Clean now.
        let r2 = run(&paths, false).unwrap();
        assert!(r2.ok, "second fsck should be clean: {:?}", r2.findings);
        assert!(r2.findings.is_empty());
    }

    /// `NoPublicKey` + `--force` → PEM block appended. Then fsck-
    /// again passes. The `disable_old_keys` is a no-op (no key lines
    /// to comment).
    #[test]
    fn no_public_key_force_fixes() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");
        // Existing config with no pubkey.
        fs::write(confbase.join("hosts/alice"), "Subnet = 10.0.0.0/24\n").unwrap();

        let r1 = run(&paths, true).unwrap();
        assert!(r1.ok, "--force should fix and pass: {:?}", r1.findings);
        assert_eq!(
            count(&r1, |f| matches!(f, Finding::FixedPublicKey { .. })),
            1
        );

        // File shape: original Subnet line preserved (no `#` —
        // disable_old_keys had nothing to match), PEM block appended.
        let host = fs::read_to_string(confbase.join("hosts/alice")).unwrap();
        assert!(host.starts_with("Subnet = 10.0.0.0/24\n"));
        assert!(host.contains("-----BEGIN ED25519 PUBLIC KEY-----"));
        assert!(!host.contains('#'));

        let r2 = run(&paths, false).unwrap();
        assert!(r2.ok, "second fsck should be clean: {:?}", r2.findings);
    }

    /// `Ed25519PublicKey` with bad b64 → `NoPublicKey` (NOT
    /// `KeyMismatch`). The `b64::decode` failure means "no usable
    /// pubkey"; we don't fall through to PEM. C `keys.c:183` —
    /// `ecdsa_set_base64_public_key` returns NULL on bad b64, and
    /// `read_ecdsa_public_key` returns that NULL, no PEM fallback.
    #[test]
    fn bad_b64_is_no_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // Bad b64: `!` isn't in the alphabet.
        fs::write(
            confbase.join("hosts/alice"),
            "Ed25519PublicKey = !!!!!!!!!!!\n",
        )
        .unwrap();

        let r = run(&paths, false).unwrap();
        assert!(!r.ok);
        // NoPublicKey, not KeyMismatch — "no usable pubkey".
        assert_eq!(count(&r, |f| matches!(f, Finding::NoPublicKey { .. })), 1);
        assert_eq!(count(&r, |f| matches!(f, Finding::KeyMismatch { .. })), 0);
    }

    /// PEM-form pubkey in hosts file works (the fallback path).
    /// fsck `--force` writes PEM, so fsck-after-fsck-force must read
    /// PEM. Covered implicitly by `key_mismatch_force_fixes`; this
    /// covers it explicitly with a hand-written PEM.
    #[test]
    fn pem_pubkey_read() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // Read the *correct* pubkey from the priv key.
        let sk = keypair::read_private(&confbase.join("ed25519_key.priv")).unwrap();
        let pk = sk.public_key();

        // Write it as PEM, not config-line.
        let mut buf = Vec::new();
        tinc_conf::pem::write_pem(&mut buf, TY_PUBLIC, pk).unwrap();
        fs::write(confbase.join("hosts/alice"), &buf).unwrap();

        let r = run(&paths, false).unwrap();
        assert!(r.ok, "PEM-form pubkey should pass: {:?}", r.findings);
    }

    // Phase 3: Key file mode

    /// 0640 priv key → `UnsafeKeyMode` warning. Doesn't fail fsck
    /// (it's a warning, and the keypair check still passes).
    #[cfg(unix)]
    #[test]
    fn unsafe_key_mode_warns() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let priv_path = confbase.join("ed25519_key.priv");
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o640)).unwrap();

        let r = run(&paths, false).unwrap();
        // Still ok — it's a warning, not an error. The C returns
        // success here too (mode check is `void`, doesn't contribute
        // to `success`).
        assert!(r.ok);
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::UnsafeKeyMode { .. }))
            .unwrap();
        // We own the file (we just created it).
        assert!(matches!(
            f,
            Finding::UnsafeKeyMode {
                uid_match: true,
                ..
            }
        ));
        // The mode is what we set, modulo type bits.
        let Finding::UnsafeKeyMode { mode, .. } = f else {
            unreachable!()
        };
        assert_eq!(mode & 0o777, 0o640);
    }

    /// 0640 + `--force` → `FixedMode`, file is now 0600.
    #[cfg(unix)]
    #[test]
    fn unsafe_key_mode_force_fixes() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let priv_path = confbase.join("ed25519_key.priv");
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o640)).unwrap();

        let r = run(&paths, true).unwrap();
        assert!(r.ok);
        assert_eq!(count(&r, |f| matches!(f, Finding::FixedMode { .. })), 1);

        // C `fsck.c:220`: `chmod(fname, st.st_mode & ~077u)`. From
        // 0640: `0640 & ~077 = 0600`. Verify.
        let mode = fs::metadata(&priv_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // Phase 4: Scripts

    /// `tinc-up` made non-executable → `ScriptNotExecutable`.
    #[cfg(unix)]
    #[test]
    fn script_not_exec_warns() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // init creates tinc-up at 0755. Chmod it down.
        let up = confbase.join("tinc-up");
        fs::set_permissions(&up, fs::Permissions::from_mode(0o644)).unwrap();

        let r = run(&paths, false).unwrap();
        // Warning, not error. C: `check_config_mode` always returns
        // true (`fsck.c:444`), regardless.
        assert!(r.ok);
        assert_eq!(
            count(&r, |f| matches!(f, Finding::ScriptNotExecutable { .. })),
            1
        );
    }

    /// Non-exec + `--force` → `chmod 0755`.
    #[cfg(unix)]
    #[test]
    fn script_not_exec_force_fixes() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let up = confbase.join("tinc-up");
        fs::set_permissions(&up, fs::Permissions::from_mode(0o644)).unwrap();

        let r = run(&paths, true).unwrap();
        assert!(r.ok);
        assert_eq!(count(&r, |f| matches!(f, Finding::FixedMode { .. })), 1);

        let mode = fs::metadata(&up).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    /// `mystery-up` in confbase → `UnknownScript`. The `*-up`/`*-down`
    /// suffix matches but the prefix isn't tinc/host/subnet.
    #[test]
    fn unknown_script() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        fs::write(confbase.join("mystery-up"), "#!/bin/sh\n").unwrap();

        let r = run(&paths, false).unwrap();
        // Warning only.
        assert!(r.ok);
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::UnknownScript { .. }))
            .unwrap();
        let Finding::UnknownScript { path } = f else {
            unreachable!()
        };
        assert!(path.ends_with("mystery-up"));
    }

    /// All six valid prefixes recognized. The full set: `tinc`,
    /// `host`, `subnet` × `-up`, `-down`.
    #[cfg(unix)]
    #[test]
    fn all_known_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // init created tinc-up. Add the others.
        for s in &[
            "tinc-down",
            "host-up",
            "host-down",
            "subnet-up",
            "subnet-down",
        ] {
            let p = confbase.join(s);
            fs::write(&p, "#!/bin/sh\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let r = run(&paths, false).unwrap();
        assert!(r.ok);
        // No UnknownScript, no ScriptNotExecutable.
        assert_eq!(count(&r, |f| matches!(f, Finding::UnknownScript { .. })), 0);
        assert_eq!(
            count(&r, |f| matches!(f, Finding::ScriptNotExecutable { .. })),
            0
        );
    }

    /// `hosts/alice-up` (per-host script) is checked for executability
    /// but NOT for prefix validity. Any `*-up` in `hosts/` is a node
    /// script. C `check_script_hostdir` (`fsck.c:495`).
    #[cfg(unix)]
    #[test]
    fn host_scripts_any_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // `whatever-up` would be unknown in confbase. In hosts/ it's
        // "the script for node `whatever`".
        let s = confbase.join("hosts/whatever-up");
        fs::write(&s, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&s, fs::Permissions::from_mode(0o644)).unwrap();

        let r = run(&paths, false).unwrap();
        // No UnknownScript (hosts/ doesn't validate prefix).
        assert_eq!(count(&r, |f| matches!(f, Finding::UnknownScript { .. })), 0);
        // BUT: not executable, so warned.
        assert_eq!(
            count(&r, |f| matches!(f, Finding::ScriptNotExecutable { .. })),
            1
        );
    }

    /// Non-script files in confbase are ignored. `tinc.conf`,
    /// `ed25519_key.priv` etc. don't end in `-up`/`-down`.
    #[test]
    fn non_scripts_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // A junk file with no -up/-down suffix.
        fs::write(confbase.join("README"), "hello\n").unwrap();
        // A file ending in `-up` but not as a suffix-match: nope,
        // `-up` IS a suffix match. Let's do something that almost
        // matches: `-ups`.
        fs::write(confbase.join("backup-ups"), "data\n").unwrap();

        let r = run(&paths, false).unwrap();
        // Neither is a script. Zero script-related findings.
        assert_eq!(
            count(&r, |f| matches!(
                f,
                Finding::UnknownScript { .. }
                    | Finding::ScriptNotExecutable { .. }
                    | Finding::ScriptAccessError { .. }
            )),
            0
        );
    }

    // Phase 5: Variables

    /// `GraphDumpFile` in tinc.conf → `ObsoleteVar`.
    #[test]
    fn obsolete_var() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let mut tc = fs::OpenOptions::new()
            .append(true)
            .open(confbase.join("tinc.conf"))
            .unwrap();
        writeln!(tc, "GraphDumpFile = /tmp/graph").unwrap();

        let r = run(&paths, false).unwrap();
        // Warning only.
        assert!(r.ok);
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::ObsoleteVar { .. }))
            .unwrap();
        let Finding::ObsoleteVar { name, .. } = f else {
            unreachable!()
        };
        // User's case preserved (we typed `GraphDumpFile`; that's
        // what's in entry.variable).
        assert_eq!(name, "GraphDumpFile");
    }

    /// `Port` in tinc.conf → `HostVarInServer`. The most common
    /// real-world warning. `Port` is `VAR_HOST` only — your own port
    /// goes in `hosts/YOU`, not `tinc.conf`.
    #[test]
    fn host_var_in_server() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let mut tc = fs::OpenOptions::new()
            .append(true)
            .open(confbase.join("tinc.conf"))
            .unwrap();
        writeln!(tc, "Port = 655").unwrap();

        let r = run(&paths, false).unwrap();
        assert!(r.ok); // warning
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::HostVarInServer { .. }))
            .unwrap();
        let Finding::HostVarInServer { name, source } = f else {
            unreachable!()
        };
        assert_eq!(name, "Port");
        // Source carries the file + line. tinc.conf, line 2 (init
        // wrote `Name = alice` on line 1).
        let Source::File { path, line } = source else {
            panic!("expected File source")
        };
        assert!(path.ends_with("tinc.conf"));
        assert_eq!(*line, 2);
    }

    /// `Device` in `hosts/alice` → `ServerVarInHost`. Rarer; here
    /// for symmetry.
    #[test]
    fn server_var_in_host() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let mut hf = fs::OpenOptions::new()
            .append(true)
            .open(confbase.join("hosts/alice"))
            .unwrap();
        writeln!(hf, "Device = /dev/net/tun").unwrap();

        let r = run(&paths, false).unwrap();
        assert!(r.ok);
        assert_eq!(
            count(&r, |f| matches!(f, Finding::ServerVarInHost { .. })),
            1
        );
    }

    /// Two `Name =` lines → `DuplicateVar`. `Name` is non-MULTIPLE.
    /// **The only place that surfaces silent-first-wins** — the
    /// daemon would silently use the first.
    #[test]
    fn duplicate_non_multiple() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let mut tc = fs::OpenOptions::new()
            .append(true)
            .open(confbase.join("tinc.conf"))
            .unwrap();
        writeln!(tc, "Name = bob").unwrap();

        let r = run(&paths, false).unwrap();
        assert!(r.ok);
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::DuplicateVar { .. }))
            .unwrap();
        let Finding::DuplicateVar { name, where_ } = f else {
            unreachable!()
        };
        // Canonical case from VARS, not user's case.
        assert_eq!(name, "Name");
        // C `fsck.c:188`: `nodename ? nodename : "tinc.conf"`.
        // Server check → "tinc.conf".
        assert_eq!(where_, "tinc.conf");
    }

    /// Two `Subnet =` lines → NO duplicate warning. `Subnet` is
    /// `VAR_MULTIPLE`. Multi-homed nodes have many subnets.
    #[test]
    fn duplicate_multiple_ok() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let mut hf = fs::OpenOptions::new()
            .append(true)
            .open(confbase.join("hosts/alice"))
            .unwrap();
        writeln!(hf, "Subnet = 10.0.0.0/24").unwrap();
        writeln!(hf, "Subnet = 10.1.0.0/24").unwrap();

        let r = run(&paths, false).unwrap();
        assert!(r.ok);
        assert_eq!(count(&r, |f| matches!(f, Finding::DuplicateVar { .. })), 0);
    }

    /// Unknown var → silent skip. NOT a warning. C `fsck.c:164`.
    /// The TODO(feature) case.
    #[test]
    fn unknown_var_silent() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        let mut tc = fs::OpenOptions::new()
            .append(true)
            .open(confbase.join("tinc.conf"))
            .unwrap();
        // Typo: `Prot` instead of `Port`. Not in VARS.
        writeln!(tc, "Prot = 655").unwrap();

        let r = run(&paths, false).unwrap();
        assert!(r.ok);
        // Nothing. The typo is invisible. fsck-the-port matches C;
        // fsck-the-feature would warn here. Noted as a future TODO.
        assert!(r.findings.is_empty(), "{:?}", r.findings);
    }

    /// Variable check runs on ALL hosts files, not just `hosts/MYNAME`.
    /// C `fsck.c:613`: iterate `hosts/`, `check_conffile` each.
    #[test]
    fn checks_all_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // Create hosts/bob with a server-only var.
        fs::write(
            confbase.join("hosts/bob"),
            "Ed25519PublicKey = abc\nDevice = /dev/foo\n",
        )
        .unwrap();

        let r = run(&paths, false).unwrap();
        // The Device line in hosts/bob.
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::ServerVarInHost { .. }))
            .unwrap();
        let Finding::ServerVarInHost { source, .. } = f else {
            unreachable!()
        };
        let Source::File { path, .. } = source else {
            panic!("expected File source")
        };
        assert!(path.ends_with("hosts/bob"));
    }

    /// `hosts/` entries failing `check_id` are skipped. `.dotfile`,
    /// `with-dash`, etc. — not valid node names, so not host files.
    #[test]
    fn hosts_non_id_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        // Dash isn't valid in node names. (C `check_id`: `[A-Za-z0-9_]+`.)
        // This file has a server-only var, but it's not a host file
        // because the name is invalid → no warning.
        fs::write(confbase.join("hosts/with-dash"), "Device = /dev/foo\n").unwrap();

        let r = run(&paths, false).unwrap();
        assert_eq!(
            count(&r, |f| matches!(f, Finding::ServerVarInHost { .. })),
            0
        );
    }

    /// `conf.d/*.conf` is included in the variable check. The
    /// 40719189 fix in `read_server_config` carries through here:
    /// fsck on a `conf.d/` config actually checks `conf.d/`.
    #[test]
    fn confd_checked() {
        let dir = tempfile::tempdir().unwrap();
        let (confbase, paths) = paths_at(&dir);
        init(&paths, "alice");

        fs::create_dir(confbase.join("conf.d")).unwrap();
        // Port is HOST-only.
        fs::write(confbase.join("conf.d/10-net.conf"), "Port = 655\n").unwrap();

        let r = run(&paths, false).unwrap();
        let f = r
            .findings
            .iter()
            .find(|f| matches!(f, Finding::HostVarInServer { .. }))
            .unwrap();
        let Finding::HostVarInServer { source, .. } = f else {
            unreachable!()
        };
        let Source::File { path, .. } = source else {
            panic!("expected File source")
        };
        // The 40719189-ported behavior: this finding *exists*. HEAD
        // C would never read this file.
        assert!(path.ends_with("10-net.conf"));
    }

    // Display formatting smoke tests

    /// Every variant has a `Display` impl. Exhaustiveness check.
    /// (The match in `Display` is already exhaustive — Rust enforces
    /// it. This tests that no variant `panic!`s in formatting, and
    /// that the messages contain the expected user-greppable bits.)
    #[test]
    fn display_exhaustive() {
        use Finding as F;
        let p = PathBuf::from("/x/y");
        let s = Source::File {
            path: p.clone(),
            line: 5,
        };
        // One of each variant. Format and check for the key phrase.
        let cases: &[(Finding, &str)] = &[
            (F::TincConfMissing, "No such file"),
            (
                F::TincConfDenied {
                    running_as_root: false,
                },
                "sudo",
            ),
            (
                F::TincConfDenied {
                    running_as_root: true,
                },
                "permissions of each",
            ),
            (F::NoName, "valid Name"),
            (F::ConfigReadFailed("err".into()), "err"),
            (F::NoPrivateKey { path: p.clone() }, "Ed25519 private"),
            (
                F::NoPublicKey {
                    host_file: p.clone(),
                },
                "public Ed25519",
            ),
            (
                F::KeyMismatch {
                    host_file: p.clone(),
                },
                "do not match",
            ),
            (
                F::HostFileUnreadable {
                    host_file: p.clone(),
                },
                "/x/y",
            ),
            (
                F::UnsafeKeyMode {
                    path: p.clone(),
                    mode: 0o640,
                    uid_match: true,
                },
                "0640",
            ),
            (
                F::UnsafeKeyMode {
                    path: p.clone(),
                    mode: 0o640,
                    uid_match: false,
                },
                "same uid",
            ),
            (F::UnknownScript { path: p.clone() }, "tinc-up, tinc-down"),
            (F::ScriptNotExecutable { path: p.clone() }, "execute"),
            (
                F::ScriptAccessError {
                    path: p.clone(),
                    err: "e".into(),
                },
                "/x/y: e",
            ),
            (
                F::DirUnreadable {
                    path: p.clone(),
                    err: "e".into(),
                },
                "directory",
            ),
            (
                F::ObsoleteVar {
                    name: "X".into(),
                    source: s.clone(),
                },
                "obsolete",
            ),
            (
                F::HostVarInServer {
                    name: "X".into(),
                    source: s.clone(),
                },
                "server config",
            ),
            (
                F::ServerVarInHost {
                    name: "X".into(),
                    source: s.clone(),
                },
                "host config",
            ),
            (
                F::DuplicateVar {
                    name: "X".into(),
                    where_: "tinc.conf".into(),
                },
                "multiple",
            ),
            (F::FixedMode { path: p.clone() }, "Fixed permissions"),
            (F::FixedPublicKey { path: p.clone() }, "Wrote Ed25519"),
            (
                F::FixFailed {
                    path: p.clone(),
                    err: "e".into(),
                },
                "could not fix",
            ),
        ];
        for (f, needle) in cases {
            let formatted = f.to_string();
            assert!(
                formatted.contains(needle),
                "expected `{needle}` in `{formatted}`"
            );
        }
    }

    /// Severity assignments. Spot-check the three buckets.
    #[test]
    fn severity_buckets() {
        assert_eq!(Finding::TincConfMissing.severity(), Severity::Error);
        assert_eq!(
            Finding::ObsoleteVar {
                name: "x".into(),
                source: Source::Cmdline { line: 0 }
            }
            .severity(),
            Severity::Warning
        );
        assert_eq!(
            Finding::FixedMode {
                path: PathBuf::from("/x")
            }
            .severity(),
            Severity::Info
        );
    }
}
