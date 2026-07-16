//! `tinc get`/`set`/`add`/`del` — the config-editing subcommand.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tinc_conf::vars::{self, VarFlags};

use super::{CmdError, TmpGuard, exchange, io_err};
use crate::names::{self, Paths};

/// The four operations after argv normalization; `get` with a value has
/// already been coerced to `Set` before the file walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Get,
    Set,
    Add,
    Del,
}

/// Fully-resolved intent: argv → `Intent` → file walk. Tests can construct
/// `Intent` directly to exercise the file walk without going through argv.
///
/// `node = None` means `tinc.conf`; `node = Some(n)` means `hosts/n`.
#[derive(Debug)]
pub struct Intent {
    /// What to do. After all coercions (get-with-value → set,
    /// add-on-single → set).
    pub action: Action,
    /// Canonical-case variable name (`port` in argv → `Port`). Unknown vars
    /// keep the user's casing — there's nothing to canonicalize against.
    pub variable: String,
    /// Value to set/add, or the filter for del. Empty for `Get`.
    pub value: String,
    /// `Some(name)` → `hosts/name`. `None` → `tinc.conf`.
    pub node: Option<String>,
    /// `warnonremove`: warn when a `set` replaces an existing value
    /// or when a `set` on a MULTIPLE var deletes siblings. Set when
    /// the action coercion fired (the user *intended* something
    /// gentler than what's about to happen).
    pub warn_on_remove: bool,
}

/// Warnings collected during validation; the binary prints them to stderr.
/// An enum (not strings) so tests can `matches!` on the warning kind.
#[derive(Debug)]
pub enum Warning {
    /// `--force` set on an `OBSOLETE` var.
    Obsolete(String),
    /// `--force` set on a `node.VAR` write where VAR isn't `HOST`.
    NotHostVar(String),
    /// `--force` or get/del on an unknown var.
    Unknown(String),
    /// File walk: `set` is about to replace `<var> = <oldval>` with
    /// `<var> = <newval>`. Emitted once per replaced line.
    Removing { variable: String, old_value: String },
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Warning::Obsolete(v) => {
                write!(f, "Warning: {v} is an obsolete variable!")
            }
            Warning::NotHostVar(v) => {
                write!(f, "Warning: {v} is not a host configuration variable!")
            }
            Warning::Unknown(v) => {
                write!(f, "Warning: {v} is not a known configuration variable!")
            }
            Warning::Removing {
                variable,
                old_value,
            } => {
                write!(f, "Warning: removing {variable} = {old_value}")
            }
        }
    }
}

/// Parse `[NODE.]VAR [= VAL]` from a pre-joined argv string.
///
/// Returns `(node, var, val)`. `node` is `None` if no `.` in the key.
/// `val` is `""` if no value given.
///
/// # Errors
/// `var` is empty (e.g. input is `".Port"` or `"= 655"` or `""`).
fn parse_var_expr(joined: &str) -> Result<(Option<&str>, &str, &str), CmdError> {
    let (key, val) = tinc_conf::split_kv(joined);

    // `.` doesn't appear in any var name (vars table is alnum-only),
    // so `find('.')` is unambiguous.
    let (node, var) = match key.find('.') {
        Some(dot) => (Some(&key[..dot]), &key[dot + 1..]),
        None => (None, key),
    };

    if var.is_empty() {
        return Err(CmdError::BadInput("No variable given.".into()));
    }

    Ok((node, var, val))
}

/// Bundled args for [`build_intent`]. `paths` stays separate — it's
/// the environment, not the command.
pub struct ConfigCmd<'a> {
    /// Pre-coercion action from the CLI. `Get` with a value coerces
    /// to `Set` inside `build_intent`.
    pub action: Action,
    /// `Some("alice")` for `alice.Var`; `None` for the bare form.
    pub node: Option<&'a str>,
    /// Variable name, case is the user's. Looked up case-insensitively.
    pub var: &'a str,
    /// Empty `""` means "absent" — mirrors `parse_var_expr`'s output.
    /// (Kept as `&str` not `Option<&str>` to avoid churning every
    /// caller; `is_empty()` is the absence test throughout.)
    pub value: &'a str,
    /// `--force`: relax obsolete/unknown/non-host gates.
    pub force: bool,
}

/// Validate the variable, decide which file to edit, apply the
/// action coercions.
///
/// `paths` is needed because HOST-only vars with no explicit node resolve
/// to `hosts/$(get_my_name)`, which requires reading `tinc.conf`.
///
/// `cmd.force` gates: unknown vars, obsolete vars, server-var-in-hostfile.
///
/// # Errors
/// Obsolete without force, not-host without force, unknown without force,
/// `get_my_name` failed, `check_id` on node failed, set/add without value.
///
/// # Subnet validation
///
/// When `variable == "Subnet"` and a value is given, malformed or
/// non-canonical subnets are rejected early. Subnet is the only variable
/// whose value format the CLI validates; everything else is written blindly.
pub fn build_intent(
    paths: &Paths,
    cmd: &ConfigCmd<'_>,
) -> Result<(Intent, Vec<Warning>), CmdError> {
    let ConfigCmd {
        action: raw_action,
        node: explicit_node,
        var,
        value,
        force,
    } = *cmd;
    let mut warnings = Vec::new();

    // Coerce get + value → set before the table lookup, so
    // `tinc get Port 655` becomes a set regardless of Port's flags.
    let mut action = if raw_action == Action::Get && !value.is_empty() {
        Action::Set
    } else {
        raw_action
    };

    // Check for a missing value before the table lookup, so
    // `tinc set garbagename` says "no value" not "unknown variable".
    if matches!(action, Action::Set | Action::Add) && value.is_empty() {
        return Err(CmdError::BadInput("No value for variable given.".into()));
    }

    let found = vars::lookup(var);

    // Subnet is the only var with value validation; only fires when the
    // var is known and canonically named Subnet.
    if let Some(v) = found
        && v.name == "Subnet"
        && !value.is_empty()
    {
        validate_subnet(value)?;
    }

    // Canonical name from the table; unknown vars keep the user's casing.
    let canonical: String = found.map_or_else(|| var.to_owned(), |v| v.name.to_owned());

    // Obsolete check only fires for set/add — get and del on an obsolete
    // var are fine (you might be cleaning up an old config).
    if let Some(v) = found
        && v.flags.contains(VarFlags::OBSOLETE)
        && matches!(action, Action::Set | Action::Add)
    {
        if force {
            warnings.push(Warning::Obsolete(canonical.clone()));
        } else {
            return Err(CmdError::BadInput(format!(
                "{canonical} is an obsolete variable! Use --force to use it anyway."
            )));
        }
    }

    // Server-var-in-hostfile check: `tinc set alice.DeviceType tap` is
    // suspicious because DeviceType is a server-only var. Only set/add —
    // reading or deleting is fine (might be cleaning up after --force).
    let mut node: Option<String> = explicit_node.map(str::to_owned);
    if let (Some(_), Some(v)) = (&node, found)
        && !v.flags.contains(VarFlags::HOST)
        && matches!(action, Action::Set | Action::Add)
    {
        if force {
            warnings.push(Warning::NotHostVar(canonical.clone()));
        } else {
            return Err(CmdError::BadInput(format!(
                "{canonical} is not a host configuration variable! Use --force to use it anyway."
            )));
        }
    }

    // HOST-only var with no explicit node goes into my own host file
    // (hosts/$me, from `Name =` in tinc.conf). The test is "not SERVER",
    // not "is HOST": dual-tagged vars like Port stay in tinc.conf.
    if node.is_none()
        && let Some(v) = found
        && !v.flags.contains(VarFlags::SERVER)
    {
        // get_my_name's error already says "Name not found in tinc.conf".
        node = Some(exchange::get_my_name(paths)?);
    }
    // Unknown var with no explicit node goes into tinc.conf.

    // Action coercion and the two warn-on-remove cases.
    let mut warn_on_remove = false;
    if let Some(v) = found {
        let multiple = v.flags.contains(VarFlags::MULTIPLE);
        if action == Action::Add && !multiple {
            // `tinc add Port 655` → set, warn if replacing.
            warn_on_remove = true;
            action = Action::Set;
        } else if action == Action::Set && multiple {
            // `tinc set Subnet ...` deletes sibling values; warn.
            warn_on_remove = true;
        }
    }
    // Unknown var: no coercion. `add` stays `add`.

    if let Some(n) = &node
        && !names::check_id(n)
    {
        return Err(CmdError::BadInput("Invalid name for node.".into()));
    }

    // Unknown var: get/del → warning only, set/add without force → error,
    // set/add with force → warning.
    if found.is_none() {
        if force || matches!(action, Action::Get | Action::Del) {
            warnings.push(Warning::Unknown(canonical.clone()));
        } else {
            return Err(CmdError::BadInput(format!(
                "{canonical}: is not a known configuration variable! Use --force to use it anyway."
            )));
        }
    }

    Ok((
        Intent {
            action,
            variable: canonical,
            value: value.to_owned(),
            node,
            warn_on_remove,
        },
        warnings,
    ))
}

/// Subnet value validation. Kept separate because it's the one place this
/// module reaches into `tinc-proto`.
fn validate_subnet(value: &str) -> Result<(), CmdError> {
    use std::str::FromStr;
    let s = tinc_proto::Subnet::from_str(value)
        .map_err(|_| CmdError::BadInput(format!("Malformed subnet definition {value}")))?;
    // Host bits must be zero.
    if !s.is_canonical() {
        return Err(CmdError::BadInput(format!(
            "Network address and prefix length do not match: {value}"
        )));
    }
    Ok(())
}

/// `Get`: scan the file, collect matching values. Read-only.
///
/// # Errors
/// File doesn't exist or read error.
pub fn run_get(path: &std::path::Path, variable: &str) -> Result<Vec<String>, CmdError> {
    let contents = fs::read_to_string(path).map_err(io_err(path))?;

    let mut found = Vec::new();
    for line in contents.split_inclusive('\n') {
        let Some((key, val)) = split_line(line) else {
            continue;
        };
        // Case-insensitive: the variable is canonical-case from the table;
        // the file might say `port = 655`.
        if key.eq_ignore_ascii_case(variable) {
            found.push(val.to_owned());
        }
    }
    Ok(found)
}

/// `Set`/`Add`/`Del`: scan + transform + write tmpfile + rename.
///
/// `intent.action` must not be `Get` — call `run_get` for that.
///
/// # Panics
/// If `intent.action == Get`.
///
/// # Errors
/// Read failure, write failure, rename failure, or a `Del` that matched
/// zero lines. `Set` and `Add` never fail at the walk stage — if no match
/// exists, they append.
///
/// Returns the per-line `Removing` warnings.
pub fn run_edit(path: &std::path::Path, intent: &Intent) -> Result<Vec<Warning>, CmdError> {
    debug_assert_ne!(intent.action, Action::Get, "use run_get for Get");

    let contents = fs::read_to_string(path).map_err(io_err(path))?;

    // Tmpfile is cleaned up on `?` via the RAII guard.
    let (guard, mut tf) = TmpGuard::open(path, ".config.tmp")?;

    let mut already_set = false; // Set wrote its one line
    let mut removed_any = false; // Del matched something
    let mut add_dup = false; // Add found exact match
    let mut warnings = Vec::new();

    for line in contents.split_inclusive('\n') {
        // None → not a key=val line (blank/comment/PEM)
        let parsed = split_line(line);

        let matched = parsed
            .as_ref()
            .is_some_and(|(k, _)| k.eq_ignore_ascii_case(&intent.variable));

        if matched {
            // Safe: matched implies parsed.is_some().
            let (_, line_val) = parsed.unwrap();

            match intent.action {
                Action::Get => unreachable!("debug_assert above"),

                // DEL: the `continue` is the delete. Value filter is
                // case-insensitive.
                Action::Del => {
                    if intent.value.is_empty() || line_val.eq_ignore_ascii_case(&intent.value) {
                        removed_any = true;
                        continue; // ← the delete
                    }
                    // else: fall through to copy-verbatim. A line that
                    // didn't match the filter survives.
                }

                // SET: replace first match, delete the rest — this is what
                // makes SET on a MULTIPLE var dangerous (warn_on_remove).
                Action::Set => {
                    // No warning if same value: nothing is being lost.
                    if intent.warn_on_remove && !line_val.eq_ignore_ascii_case(&intent.value) {
                        warnings.push(Warning::Removing {
                            variable: intent.variable.clone(),
                            old_value: line_val.to_owned(),
                        });
                    }

                    if already_set {
                        // Second+ match: delete.
                        continue;
                    }

                    // First match: replace in-place, using the canonical
                    // case from the table (`port = 655` → `Port = 655`).
                    writeln!(tf, "{} = {}", intent.variable, intent.value).map_err(tmpfile_werr)?;
                    already_set = true;
                    continue;
                }

                // ADD: remember exact-match dup (skip append later);
                // existing line is preserved either way.
                Action::Add => {
                    if line_val.eq_ignore_ascii_case(&intent.value) {
                        add_dup = true;
                    }
                    // No continue! Fall through to copy.
                }
            }
        }

        // Copy verbatim (`split_inclusive` kept the `\n`; only the last
        // line of a no-trailing-newline file needs one added).
        tf.write_all(line.as_bytes()).map_err(tmpfile_werr)?;
        if !line.ends_with('\n') {
            tf.write_all(b"\n").map_err(tmpfile_werr)?;
        }
    }

    let needs_append = match intent.action {
        Action::Set => !already_set,
        Action::Add => !add_dup,
        Action::Del | Action::Get => false,
    };
    if needs_append {
        writeln!(tf, "{} = {}", intent.variable, intent.value).map_err(tmpfile_werr)?;
    }

    // fsync so an immediate daemon start sees the edit.
    tf.sync_all().map_err(tmpfile_werr)?;
    drop(tf);

    if intent.action == Action::Del && !removed_any {
        return Err(CmdError::BadInput(
            "No configuration variables deleted.".into(),
        ));
    }

    guard.commit()?;

    Ok(warnings)
}

/// Write error for the tmpfile. `CmdError::Io` needs a path, so we
/// use a sentinel one. The user sees `Could not access <tmpfile>:
/// <errno>` — fine, the errno is what matters (probably ENOSPC).
///
/// `clippy::needless_pass_by_value`: `.map_err(tmpfile_werr)` passes by
/// value; closure is uglier.
fn tmpfile_werr(e: std::io::Error) -> CmdError {
    CmdError::Io {
        path: PathBuf::from("<tmpfile>"),
        err: e,
    }
}

/// Parse a config-file line into `(key, val)`.
///
/// Input still carries its trailing `\n` (from `split_inclusive`), so
/// trailing whitespace is stripped here. Returns `None` for blank and
/// empty-key lines.
///
/// PEM blocks: a `-----BEGIN PUBLIC KEY-----` line tokenizes as
/// `key = "-----BEGIN"`, which never matches a variable name and thus
/// falls through to copy-verbatim.
fn split_line(line: &str) -> Option<(&str, &str)> {
    let (key, val) = tinc_conf::split_kv(line.trim_end_matches(['\t', '\r', '\n', ' ']));
    if key.is_empty() {
        None
    } else {
        Some((key, val))
    }
}

/// Result of a full config invocation. The binary turns this into
/// stdout/stderr/exit-code. Tests assert on the structure.
#[derive(Debug)]
pub enum ConfigOutput {
    /// `Get` found these values. Binary prints one per line.
    Got(Vec<String>),
    /// `Set`/`Add`/`Del` succeeded; binary fires opportunistic reload.
    Edited,
}

/// The config command end-to-end.
///
/// `joined` is the rejoined argv tail (`args.join(" ")`); the binary
/// adapter does the joining so this function takes one string.
///
/// The opportunistic reload after an edit is a binary concern; this
/// function is filesystem-only.
///
/// # Errors
/// Validation failure (unknown var without force, etc.), file missing,
/// write error, `Del` matched nothing.
///
/// # `get Port` special case
///
/// If asking for `Port` with no explicit node and the pidfile is readable,
/// the *runtime* port from the pidfile is returned instead of the configured
/// one — with `Port = 0` the daemon picks a free port and only the pidfile
/// knows it. If the pidfile is missing, fall back to scanning the config.
/// A stale pidfile therefore gives a stale port.
///
/// `paths` must have `resolve_runtime` called so the pidfile path is
/// available; that's why the binary marks the config commands `needs_daemon`.
pub fn run(
    paths: &Paths,
    raw_action: Action,
    joined: &str,
    force: bool,
) -> Result<(ConfigOutput, Vec<Warning>), CmdError> {
    let (explicit_node, var, value) = parse_var_expr(joined)?;

    // Port-from-pidfile special case: only for a plain GET of Port with no
    // explicit node. `value.is_empty()` excludes the get-with-value form,
    // which is really a set.
    if raw_action == Action::Get
        && value.is_empty()
        && explicit_node.is_none()
        && var.eq_ignore_ascii_case("Port")
    {
        // resolve_runtime must have run for pidfile() to be populated;
        // panicking here indicates a binary bug, not user error.
        let pidfile_path = paths.pidfile();
        if let Ok(pf) = crate::ctl::Pidfile::read(pidfile_path) {
            return Ok((ConfigOutput::Got(vec![pf.port]), Vec::new()));
        }
        // Pidfile missing means the daemon is down and the configured
        // port is the truth; fall through to the normal file scan.
    }

    let (intent, mut warnings) = build_intent(
        paths,
        &ConfigCmd {
            action: raw_action,
            node: explicit_node,
            var,
            value,
            force,
        },
    )?;

    let target = match &intent.node {
        Some(node) => paths.hosts_dir().join(node),
        None => paths.tinc_conf(),
    };

    match intent.action {
        Action::Get => {
            let values = run_get(&target, &intent.variable)?;
            if values.is_empty() {
                return Err(CmdError::BadInput(
                    "No matching configuration variables found.".into(),
                ));
            }
            Ok((ConfigOutput::Got(values), warnings))
        }
        Action::Set | Action::Add | Action::Del => {
            // Walk warnings (Removing) come after validation warnings.
            warnings.extend(run_edit(&target, &intent)?);
            Ok((ConfigOutput::Edited, warnings))
        }
    }
}

#[cfg(test)]
mod tests;
