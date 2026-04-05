//! Phase 4: script executability checks.

use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::names::Paths;

use super::Finding;

/// Script half of `check_scripts_and_configs` (the variable half is
/// `conf::check_variables`). Returns the `bool` that contributes to
/// `Report::ok` — `false` only if `confbase` or `hosts/` couldn't be
/// `opendir`'d.
pub(super) fn check_scripts(paths: &Paths, force: bool, findings: &mut Vec<Finding>) -> bool {
    let confbase_ok = scan_scripts_in(&paths.confbase, ScriptDir::Confbase, force, findings);
    let hosts_ok = scan_scripts_in(&paths.hosts_dir(), ScriptDir::Hosts, force, findings);
    // Upstream short-circuits (confbase fail skips hosts scan). We
    // don't — more diagnostics, and the directory-read errors are
    // independent. Tightening.
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

/// One pass over a directory looking for `*-up`/`*-down` scripts.
/// Confbase and hosts/ share 90% of this loop; the 10% is prefix
/// validation, gated on `kind`.
fn scan_scripts_in(dir: &Path, kind: ScriptDir, force: bool, findings: &mut Vec<Finding>) -> bool {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            // The dir-level failure contributes to `!ok`.
            findings.push(Finding::DirUnreadable {
                path: dir.to_owned(),
                err: e.to_string(),
            });
            return false;
        }
    };

    for ent in rd {
        // readdir entry error: skip the broken entry, keep scanning.
        // fsck on a directory with one bad entry should still check
        // the others.
        let Ok(ent) = ent else { continue };
        let fname = ent.file_name();
        let Some(fname) = fname.to_str() else {
            continue; // non-UTF-8 filenames: not scripts (scripts have
            // ASCII names by construction)
        };

        // Suffix check.
        let prefix = if let Some(p) = fname.strip_suffix("-up") {
            p
        } else if let Some(p) = fname.strip_suffix("-down") {
            p
        } else {
            continue;
        };

        // Empty-prefix case: a file literally named `-up`.
        // `strip_suffix` returns `""` → not in the allowlist →
        // unknown script. Same outcome as upstream.

        let full_path = dir.join(fname);

        // ─── Prefix validation (confbase only)
        // hosts/ skips this — any prefix is accepted as a node name.
        if matches!(kind, ScriptDir::Confbase) && !matches!(prefix, "tinc" | "host" | "subnet") {
            findings.push(Finding::UnknownScript { path: full_path });
            // Unknown scripts aren't checked for executability —
            // they shouldn't run, so who cares.
            continue;
        }

        // ─── Executability check
        // We don't have `access(2)` directly without the `nix`
        // `unistd` feature, but we can check via metadata mode bits —
        // for the *owner*. `access` checks effective UID against the
        // bits, which is more correct (you might own a 0755 file as
        // non-owner and still be able to exec it via the other-exec
        // bit). But: scripts created by `tinc init` are owned by you;
        // the case where fsck cares is "tinc-up exists but isn't +x",
        // and that's an owner-bit check 99% of the time.
        //
        // The remaining 1% (you `chown`'d your tinc-up to someone
        // else for... reasons?) gets a false positive. Acceptable.
        check_script_exec(&full_path, force, findings);
    }

    true
}

/// `R_OK | X_OK` check + optional `chmod 0755` fix.
fn check_script_exec(path: &Path, force: bool, findings: &mut Vec<Finding>) {
    #[cfg(unix)]
    {
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                // Upstream's caller ignores this return value, so
                // it's effectively just a print. Same here.
                findings.push(Finding::ScriptAccessError {
                    path: path.to_owned(),
                    err: e.to_string(),
                });
                return;
            }
        };

        let mode = meta.permissions().mode();
        // `access(R_OK | X_OK)` for the file owner: `S_IRUSR | S_IXUSR`
        // = `0o500`. We check both bits set. (See `scan_scripts_in`
        // comment for why we punt on group/other bits.)
        if mode & 0o500 == 0o500 {
            return; // executable by owner; good
        }

        findings.push(Finding::ScriptNotExecutable {
            path: path.to_owned(),
        });

        if !force {
            return;
        }

        // Hard-coded 0755, not `mode | 0o111` — fsck normalizes to
        // "the mode `tinc init` would've used". Preserves the
        // convention.
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
        // Windows: no execute bit. fsck-on-Windows doesn't really do
        // this check.
        let _ = (path, force, findings);
    }
}
