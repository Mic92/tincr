//! Phase 5: per-variable validity (obsolete/wrong-file/duplicate).

use std::fs;

use tinc_conf::{Config, VARS, VarFlags, read_server_config};

use crate::names::{Paths, check_id};

use super::Finding;

/// Scan server config + each `hosts/*` for obsolete/wrong-file/
/// duplicate vars. Warnings only; returns nothing.
///
/// Re-parses every file: wasteful — we already parsed them in Phase 1
/// — but the merged tree from Phase 1 has lost the per-file separation
/// (server vs each-host). Re-parse-per-check is the simplest way to
/// get that back. The waste is one extra pass over ~100 lines of
/// config; not worth a refactor.
pub(super) fn check_variables(paths: &Paths, findings: &mut Vec<Finding>) {
    // ─── Server config
    if let Ok(cfg) = read_server_config(&paths.confbase) {
        // `where_` for the duplicate message: literal string, not a
        // path. Slightly wrong if conf.d/*.conf is the source of the
        // duplicate — we say "tinc.conf" anyway. Upstream bug;
        // carried.
        check_conf(&cfg, true, "tinc.conf", findings);
    }
    // Read failure on server config → skip the var check. A
    // `ConfigReadFailed` was already pushed in Phase 1.

    // ─── Each host file
    // The `check_id` filter skips `.`, `..`, and any `hosts/*` that
    // isn't a valid node name (`tinc init` only creates valid-named
    // files).
    let Ok(rd) = fs::read_dir(paths.hosts_dir()) else {
        // Silent skip on opendir failure: the hosts/ dir was already
        // checked in Phase 4; the `DirUnreadable` finding is there.
        // Don't double-report.
        return;
    };
    for ent in rd {
        let Ok(ent) = ent else { continue };
        let fname = ent.file_name();
        let Some(node) = fname.to_str() else { continue };
        if !check_id(node) {
            continue;
        }

        let Ok(entries) = tinc_conf::parse_file(paths.host_file(node)) else {
            // Silent skip per-file. The host file might be
            // unparseable; that's a different fsck phase's job to
            // catch. (Upstream doesn't catch it either.)
            continue;
        };
        let mut cfg = Config::new();
        cfg.merge(entries);
        check_conf(&cfg, false, node, findings);
    }
}

/// The four warnings: obsolete, host-var-in-server,
/// server-var-in-host, duplicate-non-multiple.
///
/// `is_server`: `true` for `tinc.conf`+`conf.d/`, `false` for a
/// `hosts/NODE` file. Determines which "wrong file" check applies.
///
/// `where_`: `nodename` or `"tinc.conf"` — what to print in the
/// duplicate message. NOT a path.
fn check_conf(cfg: &Config, is_server: bool, where_: &str, findings: &mut Vec<Finding>) {
    // ─── Per-entry pass: obsolete + wrong-file
    // Index = position in `VARS` (preserved from upstream — see
    // `vars.rs` module doc). `VARS.len()` is 74, asserted at compile
    // time.
    let mut count = vec![0u32; VARS.len()];

    for entry in cfg.entries() {
        // Linear scan: we need the index for `count[idx]`, so
        // `.position()` rather than `lookup_var` (which doesn't
        // return the index).
        let Some(idx) = VARS
            .iter()
            .position(|v| v.name.eq_ignore_ascii_case(&entry.variable))
        else {
            // Unknown var: NOT a warning — see vars.rs doc.
            // TODO(feature): warn on unknown vars. Not a port; a
            // feature.
            continue;
        };
        count[idx] += 1;
        let flags = VARS[idx].flags;

        if flags.contains(VarFlags::OBSOLETE) {
            findings.push(Finding::ObsoleteVar {
                name: entry.variable.clone(),
                source: entry.source.clone(),
            });
        }

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
    // Second loop over `count[]`. Separate pass because the duplicate
    // warning is per-variable-NAME, not per-entry — it doesn't have a
    // single line number.
    for (idx, &n) in count.iter().enumerate() {
        if n > 1 && !VARS[idx].flags.contains(VarFlags::MULTIPLE) {
            findings.push(Finding::DuplicateVar {
                // Canonical case from the table, not whatever case
                // the user typed.
                name: VARS[idx].name.to_owned(),
                where_: where_.to_owned(),
            });
        }
    }
}
