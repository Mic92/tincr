//! `cmd_config` — `tinc get`/`set`/`add`/`del`. The config-editing CLI.
//!
//! Upstream's ~365-line function is dense enough to merit both a
//! NOLINT *and* a 4096-byte stack buffer pair. It does
//! one thing (edit a key-value file) but with enough policy knobs
//! (which file? canonicalize the key? validate the value? are
//! multiple values allowed? are unknown keys allowed?) that the
//! straight-line path is a forest of `if(action == ...)` arms.
//!
//! ## What it does
//!
//! Four operations on one of two files (`tinc.conf` or `hosts/NODE`):
//!
//! | Op | Effect |
//! |---|---|
//! | `get VAR` | Print all values of VAR, one per line. Exit 1 if none. |
//! | `set VAR VAL` | Replace VAR's value(s) with VAL. Appends if no match. |
//! | `add VAR VAL` | Append `VAR = VAL` unless that exact pair already exists. |
//! | `del VAR [VAL]` | Delete all VAR lines, or only those whose value matches VAL. |
//!
//! The file is decided by VAR's `VarFlags`: `SERVER` → `tinc.conf`,
//! `HOST`-only → `hosts/$(get_my_name)`. The `NODE.VAR` syntax
//! (`tinc set alice.Port 655`) overrides to `hosts/NODE`.
//!
//! ## Action coercions (the `argv++, argc--` jungle)
//!
//! Three places where the action you asked for isn't the one you get:
//!
//! 1. `get VAR VALUE` → `set VAR VALUE`. Probably a footgun but it's
//!    upstream behavior; replicating it would surprise nobody who
//!    types `tinc get Port` and adding `655` would surprise nobody
//!    who *intended* set. Kept.
//! 2. `add VAR VALUE` where VAR isn't `MULTIPLE` → `set` + warning.
//!    `tinc add Port 655` doesn't add a *second* Port line; it
//!    replaces. The warning fires if a value is being replaced.
//! 3. `set VAR VALUE` where VAR *is* `MULTIPLE` → `set` + warning.
//!    `tinc set Subnet 10.0.0.0/24` will delete every other Subnet
//!    line. You probably wanted `add`. Warning, not error —
//!    sometimes you do want a single subnet.
//!
//! ## What we drop / tighten
//!
//! - Windows `remove(filename)` before `rename`: dropped. Unix-only.
//! - `.config.tmp` cleanup on error paths. Upstream leaves it on
//!   most error returns. `TmpGuard` ensures it goes.
//! - No 4096-byte line truncation. `fgets` silently truncates and
//!   the tail becomes a new line. We use `read_to_string` +
//!   `split_inclusive`.
//!
//! ## Why this isn't `tinc_conf::Config`
//!
//! `parse_file` would lose: original casing, original whitespace,
//! the position of the matched line (set replaces in-place), the
//! PEM blocks at the bottom of host files. `cmd_config` has to be
//! a byte-preserving line walk. Same reason `copy_host_replacing_port`
//! in `invite.rs` is — it's the **seventh** instance of a manual
//! `key = val` tokenizer because the use case (preserve unmatched
//! lines verbatim) doesn't fit the parsed-tree model.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tinc_conf::vars::{self, VarFlags};

use super::{CmdError, exchange, io_err};
use crate::names::{self, Paths};

// Action enum — GET/SET/ADD/DEL after argv normalization.

/// What to do. We add `Unset` for the pre-dispatch state where
/// `get` defaults to `Get` but might become `Set` if a value is
/// given (the action-coercion).
///
/// Why not a separate `Action::Get` vs `Action::GetOrSet`: upstream
/// resolves the ambiguity *before* the file walk, so by the time we
/// open the file there are exactly four states. Matching that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Get,
    Set,
    Add,
    Del,
}

// Parsed argv — everything before we touch the filesystem

/// The intent, after all argv munging is done. This is the testable
/// seam: argv → `Intent` → file walk. Tests can construct `Intent`
/// directly to exercise the file walk without going through argv.
///
/// `node = None` means `tinc.conf`. `node = Some(n)` means
/// `hosts/n`. Upstream threads `node` through as `char*` and checks
/// it at the end; we resolve up-front.
#[derive(Debug)]
pub struct Intent {
    /// What to do. After all coercions (get-with-value → set,
    /// add-on-single → set).
    pub action: Action,
    /// Canonical-case variable name. `port` in argv → `Port` here.
    /// If the var is unknown (and `--force`), this is the user's
    /// casing — there's nothing to canonicalize against.
    pub variable: String,
    /// The value to set/add, or the filter for del. Always empty for
    /// `Get` (the get-with-value coercion happened upstream).
    pub value: String,
    /// `Some(name)` → `hosts/name`. `None` → `tinc.conf`.
    pub node: Option<String>,
    /// `warnonremove`: warn when a `set` replaces an existing value
    /// or when a `set` on a MULTIPLE var deletes siblings. Set when
    /// the action coercion fired (the user *intended* something
    /// gentler than what's about to happen).
    pub warn_on_remove: bool,
}

/// Warnings the validation layer emits to stderr. Upstream does
/// `fprintf(stderr, ...)` inline; we collect, the binary prints.
/// Tests assert on the vec.
///
/// Why an enum and not just `Vec<String>`: tests want to assert
/// "an obsolete-var warning fired", not "a string containing
/// 'obsolete' was emitted". Same `matches!` pattern as fsck's
/// `Finding`.
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
                // `=` with single space on both sides. The file
                // might have `Port=655` or `Port  =  655`; the
                // warning normalizes. (Minor info loss, but upstream
                // does the same — it prints `variable` and `bvalue`,
                // both already trimmed.)
                write!(f, "Warning: removing {variable} = {old_value}")
            }
        }
    }
}

// Stage 1: argv → (raw action, optional explicit node, var, value)

/// Parse `[NODE.]VAR [= VAL]` from a pre-joined argv string.
///
/// Same `strcspn`/`strspn` tokenizer that appears in conf parsing,
/// invitations, etc. — the SEVENTH instance. See module doc for why
/// we don't unify them.
///
/// The `node.var` split happens *after* `var = val` tokenization,
/// so `alice.Port = 655` parses as `(alice, Port, 655)` but
/// `alice.Port=655` parses as... `(alice, Port, 655)` too — the
/// `=` is in the `strcspn` stop set, so the var-end is found
/// before the `.` matters. The `.` is found by `strchr` on the
/// var portion only.
///
/// Returns `(node, var, val)`. `node` is `None` if no `.` in the
/// key. `val` is `""` if no value given. Empty `var` is a caller
/// error.
///
/// # Errors
/// `var` is empty (e.g. input is `".Port"` or `"= 655"` or `""`).
fn parse_var_expr(joined: &str) -> Result<(Option<&str>, &str, &str), CmdError> {
    // ─── Find end of key: first \t, space, or =
    // Same `find` set as `split_var` in join.rs. Those three chars
    // exactly.
    let key_end = joined.find(['\t', ' ', '=']).unwrap_or(joined.len());
    let key = &joined[..key_end];

    // ─── Walk past separator to find value
    let rest = &joined[key_end..];
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let val = rest.trim_start_matches([' ', '\t']);

    // ─── Split key on '.' for node.var syntax
    // The `.` doesn't appear in any var name (verified: `vars.rs`
    // table is alnum-only) so `find('.')` is unambiguous.
    let (node, var) = match key.find('.') {
        Some(dot) => (Some(&key[..dot]), &key[dot + 1..]),
        None => (None, key),
    };

    // ─── Empty var → error
    // `alice.` → empty var. `.` alone → empty node AND empty var,
    // but the var check fires first. We don't separately validate
    // the node here (`check_id` later).
    if var.is_empty() {
        return Err(CmdError::BadInput("No variable given.".into()));
    }

    Ok((node, var, val))
}

// Stage 2: validate against vars table, decide target file, coerce
// action. This is the C's `for(int i = 0; variables[i].name; i++)`
// loop body plus the surrounding `if(!found)` and `if(node &&
// !check_id)` checks.

/// Validate the variable, decide which file to edit, apply the
/// action coercions.
///
/// `paths` is needed because non-HOST vars on a missing-node
/// expression resolve to `hosts/$(get_my_name)`, which reads
/// `tinc.conf`.
///
/// `force` gates: unknown vars, obsolete vars, server-var-in-hostfile.
///
/// # Errors
/// Same as the C's `return 1` paths: obsolete without force,
/// not-host without force, unknown without force, `get_my_name`
/// failed, `check_id` on node failed, set/add without value.
///
/// # The Subnet validation special case
///
/// When `variable == "Subnet"` and a value is given, we parse it
/// and reject malformed/non-canonical subnets early. This is the
/// *one* case where the `variables[]` table isn't enough — Subnet
/// is the only var with a validated value format that the CLI
/// checks. (The daemon validates everything via `read_config_file`,
/// but `cmd_config` writes blindly otherwise.)
pub fn build_intent(
    paths: &Paths,
    raw_action: Action,
    explicit_node: Option<&str>,
    var: &str,
    value: &str,
    force: bool,
) -> Result<(Intent, Vec<Warning>), CmdError> {
    let mut warnings = Vec::new();

    // ─── Action coercion: get + value → set
    // Happens BEFORE the table lookup — `tinc get Port 655` becomes
    // a `set` regardless of Port's flags.
    let mut action = if raw_action == Action::Get && !value.is_empty() {
        Action::Set
    } else {
        raw_action
    };

    // ─── set/add need a value
    // Check is BEFORE table lookup — we keep that ordering so
    // `tinc set garbagename` says "no value" not "unknown variable".
    if matches!(action, Action::Set | Action::Add) && value.is_empty() {
        return Err(CmdError::BadInput("No value for variable given.".into()));
    }

    // ─── Look up in the variables table
    // Linear scan, `strcasecmp` match. ~80 entries; O(n) is fine.
    let found = vars::lookup(var);

    // ─── Subnet special case: validate value early
    // The check is inside the table-scan loop body (after
    // `found = true`), so it only fires if the var is known AND
    // named Subnet. Case-insensitive via `lookup` + checking the
    // canonical table name.
    if let Some(v) = found
        && v.name == "Subnet"
        && !value.is_empty()
    {
        validate_subnet(value)?;
    }

    // ─── Canonical name from the table
    // If unknown, the user's casing survives.
    let canonical: String = found.map_or_else(|| var.to_owned(), |v| v.name.to_owned());

    // ─── Obsolete check
    // Only fires for set/add — `get` and `del` on an obsolete var
    // are fine (you might be cleaning up an old config).
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

    // ─── Server-var-in-hostfile check
    // `node.VAR` where VAR isn't HOST. `tinc set alice.DeviceType
    // tap` is suspicious — DeviceType is a server-only var, why are
    // you putting it in alice's host file? Again only set/add —
    // reading or deleting one is fine (might be cleaning up after a
    // previous --force).
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

    // ─── HOST-only var with no explicit node → my host file
    // `tinc set Subnet 10.0.0.0/24` — Subnet is HOST-only, no
    // `node.` prefix, so where does it go? `get_my_name` reads
    // tinc.conf, finds `Name =`, returns it.
    //
    // The condition is `!node && !(type & VAR_SERVER)` — note it's
    // NOT `type & VAR_HOST`. The dual-tagged vars (e.g. `Port`,
    // both SERVER and HOST) take the SERVER path here → they go in
    // tinc.conf. Single-HOST-only goes in hosts/$me.
    if node.is_none()
        && let Some(v) = found
        && !v.flags.contains(VarFlags::SERVER)
    {
        // get_my_name's error already says "Name not found
        // in tinc.conf"; we don't wrap.
        node = Some(exchange::get_my_name(paths)?);
    }
    // If not found AND no explicit node: tinc.conf. Unknown vars go
    // in the server config unless you say otherwise.

    // ─── Action coercion: add on non-MULTIPLE → set
    // The two `warnonremove` cases.
    let mut warn_on_remove = false;
    if let Some(v) = found {
        let multiple = v.flags.contains(VarFlags::MULTIPLE);
        if action == Action::Add && !multiple {
            // `tinc add Port 655` → set, warn if replacing.
            warn_on_remove = true;
            action = Action::Set;
        } else if action == Action::Set && multiple {
            // `tinc set Subnet 10.0.0.0/24` → still set, warn that
            // you're nuking the other subnets.
            warn_on_remove = true;
        }
    }
    // Unknown var: no coercion. `add` stays `add`.

    // ─── check_id on node
    if let Some(n) = &node
        && !names::check_id(n)
    {
        return Err(CmdError::BadInput("Invalid name for node.".into()));
    }

    // ─── Unknown var
    // Three-way: get/del → warning only, set/add without force →
    // error, set/add with force → warning. The warning's `:`
    // placement differs between the two upstream messages
    // (`"Warning: %s is..."` vs `"%s: is..."`) — likely a typo;
    // we keep ours consistent.
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

/// Subnet value validation.
///
/// Splits into a separate function because it's the one place
/// `cmd_config` reaches into `tinc-proto`. The dep is justified
/// (see Cargo.toml comment) but isolating it makes the boundary
/// visible.
fn validate_subnet(value: &str) -> Result<(), CmdError> {
    use std::str::FromStr;
    let s = tinc_proto::Subnet::from_str(value)
        .map_err(|_| CmdError::BadInput(format!("Malformed subnet definition {value}")))?;
    // `is_canonical`: host bits must be zero.
    if !s.is_canonical() {
        return Err(CmdError::BadInput(format!(
            "Network address and prefix length do not match: {value}"
        )));
    }
    Ok(())
}

// Stage 3: the file walk. Read, transform, write-via-tmpfile, rename.

/// Result of a `Get`. Values found, in file order.
///
/// The binary prints one per line. Separate type so tests can
/// assert without capturing stdout.
pub type GetResult = Vec<String>;

/// Result of a `Set`/`Add`/`Del`. The walk produces warnings as a
/// side effect (gathered by the caller); the bool is "did anything
/// change?" — `Del` returns error if it didn't delete anything,
/// `Set`/`Add` always succeed.
#[derive(Debug)]
pub struct EditResult {
    /// Any line was added, replaced, or removed.
    pub changed: bool,
    /// Per-line `Removing` warnings. Separate from the validation
    /// warnings because they come from the walk, not the lookup.
    pub warnings: Vec<Warning>,
}

/// `<path>.config.tmp` RAII. Same shape as `genkey::TmpGuard` but
/// the suffix differs (`.config.tmp` vs `.tmp`). Re-declared here
/// per the "module-private constants stay private" rule — the two
/// guards have different invariants (genkey's is about commenting
/// out PEM blocks; this one is about config-line surgery) and
/// unifying them would create a false coupling.
///
/// Drop = `unlink` best-effort. `commit()` consumes self, renames,
/// drop is a no-op.
struct TmpGuard {
    tmp: PathBuf,
    target: PathBuf,
}

impl TmpGuard {
    /// Open `<target>.config.tmp` for writing.
    ///
    /// We `O_CREAT | O_TRUNC | O_WRONLY` at mode 0644 — same as
    /// `fopen("w")` under default umask. The target is a config
    /// file, not a key file; world-read is fine.
    fn open(target: &std::path::Path) -> Result<(Self, fs::File), CmdError> {
        // The `.config.tmp` suffix is exactly upstream's. Can't use
        // `with_extension` — that'd replace `.conf`, not append.
        let mut tmp = target.as_os_str().to_owned();
        tmp.push(".config.tmp");
        let tmp = PathBuf::from(tmp);

        // Create-or-truncate. If a `.config.tmp` is lying around
        // from a crashed previous run, we just overwrite it.
        //
        // Our `CmdError::Io` says "Could not access <path>: <err>".
        // The path identifies the file (it ends in `.config.tmp`);
        // the io::Error says what went wrong.
        let f = fs::File::create(&tmp).map_err(io_err(&tmp))?;

        Ok((
            Self {
                tmp,
                target: target.to_path_buf(),
            },
            f,
        ))
    }

    /// Rename tmp → target. Consumes self; drop becomes a no-op.
    ///
    /// `mem::take` on the path because we can't destructure a Drop
    /// type (E0509). After the take, `self.tmp` is empty `PathBuf`;
    /// when `self` drops at function end (after rename succeeded),
    /// `remove_file("")` is an `ENOENT` no-op. If rename FAILS, we
    /// manually unlink before the take'd `tmp` drops.
    fn commit(mut self) -> Result<(), CmdError> {
        let tmp = std::mem::take(&mut self.tmp);
        let target = std::mem::take(&mut self.target);
        // self.tmp is now empty. Drop will `remove_file("")` →
        // ENOENT → silently ignored. Harmless.

        fs::rename(&tmp, &target).map_err(|e| {
            // Best-effort cleanup. If rename fails (cross-device?
            // perms?) we shouldn't leave `.config.tmp` lying around.
            // Upstream doesn't do this — it just `return 1`s. We
            // tighten.
            let _ = fs::remove_file(&tmp);
            // Our Io variant only carries one path; we pick the
            // target (it's the file the user asked about).
            CmdError::Io {
                path: target,
                err: e,
            }
        })
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        // Only fires on error returns (`?` propagation). On the
        // success path, `commit()` consumes self before drop.
        // Upstream doesn't unlink on error returns; we do. Harmless
        // if the file's already gone (`ENOENT` from `remove_file`
        // is silently dropped).
        let _ = fs::remove_file(&self.tmp);
    }
}

/// `Get`: scan the file, collect matching values.
///
/// Doesn't open a tmpfile — read-only.
///
/// # Errors
/// File doesn't exist (`fopen` fails) or read error.
pub fn run_get(path: &std::path::Path, variable: &str) -> Result<GetResult, CmdError> {
    let contents = fs::read_to_string(path).map_err(io_err(path))?;

    let mut found = Vec::new();
    // `split_inclusive` because we don't care about the newline
    // here (we trim it off the value anyway), but it keeps the
    // shape consistent with `run_edit` where the newline matters.
    for line in contents.split_inclusive('\n') {
        let Some((key, val)) = split_line(line) else {
            continue;
        };
        // `eq_ignore_ascii_case`: the variable is canonical-case
        // from the table; the file might say `port = 655`.
        if key.eq_ignore_ascii_case(variable) {
            found.push(val.to_owned());
        }
    }
    Ok(found)
}

/// `Set`/`Add`/`Del`: scan + transform + write tmpfile + rename.
///
/// `intent.action` MUST NOT be `Get` — call `run_get` for that.
/// (Debug-asserted; the binary's adapter routes correctly.)
///
/// # Panics
/// `intent.action == Get` (use `run_get`). The `unreachable!` is
/// the release-mode mirror of the `debug_assert_ne` at function
/// entry. The `parsed.unwrap()` inside the loop is statically safe
/// (it's behind an `is_some_and` guard); allowed via lint rather
/// than refactored to nested `if let` because the latter would
/// need a 60-line indent shift for zero behavioral difference.
///
/// # Errors
/// Read failure, write failure, rename failure. Also: `Del` that
/// matched zero lines (`"No configuration variables deleted."`).
///
/// The `Set` and `Add` cases never fail at the walk stage — if no
/// match exists, they append.
// missing_panics_doc: the unwrap is provably safe behind is_some_and
// but clippy can't see across statements.
#[allow(clippy::missing_panics_doc)] // unwrap guarded by is_some_and; clippy can't see across statements
pub fn run_edit(path: &std::path::Path, intent: &Intent) -> Result<EditResult, CmdError> {
    debug_assert_ne!(intent.action, Action::Get, "use run_get for Get");

    // ─── Read whole file
    // We can `read_to_string` — config files are kilobytes.
    let contents = fs::read_to_string(path).map_err(io_err(path))?;

    // ─── Open tmpfile (RAII; cleaned up on `?`)
    let (guard, mut tf) = TmpGuard::open(path)?;

    // ─── Walk lines
    let mut already_set = false; // Set wrote its one line
    let mut removed_any = false; // Del matched something
    let mut add_dup = false; // Add found exact match
    let mut warnings = Vec::new();

    for line in contents.split_inclusive('\n') {
        // ─── Tokenize. None → not a key=val line (blank/comment/PEM)
        let parsed = split_line(line);

        // ─── Match against our variable
        // The big four-arm dispatch.
        let matched = parsed
            .as_ref()
            .is_some_and(|(k, _)| k.eq_ignore_ascii_case(&intent.variable));

        if matched {
            // Safe: matched implies parsed.is_some().
            let (_, line_val) = parsed.unwrap();

            match intent.action {
                Action::Get => unreachable!("debug_assert above"),

                // ─── DEL: skip if value matches (or no filter)
                // The `continue` is the delete — we just don't
                // write the line. Value filter is case-insensitive.
                // `tinc del ConnectTo alice` matches `ConnectTo =
                // Alice`.
                Action::Del => {
                    if intent.value.is_empty() || line_val.eq_ignore_ascii_case(&intent.value) {
                        removed_any = true;
                        continue; // ← the delete
                    }
                    // else: fall through to copy-verbatim. A Subnet
                    // line that didn't match the filter survives.
                }

                // ─── SET: replace first match, delete rest
                // The first-match-replaces, subsequent-matches-delete
                // behavior is what makes SET on a MULTIPLE var
                // dangerous (warnonremove).
                Action::Set => {
                    // Warning fires for *every* deleted/replaced
                    // line whose value differs from the new one.
                    // Same value → no warning (you're setting it to
                    // what it already was; nothing's being lost).
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

                    // First match: replace in-place. Note: canonical
                    // case for the key, *not* the file's casing.
                    // `port = 655` in → `Port = 655` out. Intentional
                    // (the table is the canon).
                    writeln!(tf, "{} = {}", intent.variable, intent.value).map_err(tmpfile_werr)?;
                    already_set = true;
                    continue;
                }

                // ─── ADD: check for dup, fall through to copy
                // If exact match exists, remember it (we'll skip the
                // append at the end). Either way, the existing line
                // is preserved.
                Action::Add => {
                    if line_val.eq_ignore_ascii_case(&intent.value) {
                        add_dup = true;
                    }
                    // No continue! Fall through to copy.
                }
            }
        }

        // ─── Copy verbatim
        // Includes the "add newline if missing" — last line might
        // not have `\n`. `split_inclusive` gives us the trailing
        // `\n` if it was there, so we write `line` directly. The
        // "add newline if missing" check translates to: if `line`
        // doesn't end with `\n` (only true for the last line of a
        // file with no trailing newline), add one.
        tf.write_all(line.as_bytes()).map_err(tmpfile_werr)?;
        if !line.ends_with('\n') {
            tf.write_all(b"\n").map_err(tmpfile_werr)?;
        }
    }

    // ─── Append if needed
    // `Set` that matched nothing appends; `Add` that found no dup
    // appends.
    let needs_append = match intent.action {
        Action::Set => !already_set,
        Action::Add => !add_dup,
        Action::Del | Action::Get => false,
    };
    if needs_append {
        writeln!(tf, "{} = {}", intent.variable, intent.value).map_err(tmpfile_werr)?;
    }

    // ─── Flush + close
    // Dropping `tf` flushes implicitly, but `sync_all` makes the
    // error visible. Upstream checks `fclose`'s return; we go
    // further (fsync). Config edits matter — `tinc set Port 655`
    // followed by an immediate daemon start should see the new port.
    tf.sync_all().map_err(tmpfile_werr)?;
    drop(tf);

    // ─── Del with nothing deleted → error
    // GET never reaches here (we routed it to run_get).
    // TmpGuard::drop handles the tmpfile cleanup on the `?`.
    if intent.action == Action::Del && !removed_any {
        return Err(CmdError::BadInput(
            "No configuration variables deleted.".into(),
        ));
    }

    // ─── Commit: rename tmp → target
    guard.commit()?;

    // `changed` is for the binary to decide whether to reload.
    // Set/Add always change (either replaced or appended). Del
    // changed iff removed_any (and we already returned error
    // for !removed_any, so always true here). But: a SET that
    // replaced a value with itself? The file's still rewritten
    // (canonical casing might differ), so still "changed" from
    // the daemon's perspective. Keep it simple: we got here →
    // changed.
    Ok(EditResult {
        changed: true,
        warnings,
    })
}

/// Write error for the tmpfile. `CmdError::Io` needs a path, so we
/// use a sentinel one. The user sees `Could not access <tmpfile>:
/// <errno>` — fine, the errno is what matters (probably ENOSPC).
///
/// `clippy::needless_pass_by_value`: same shape as `daemon_err` in
/// `ctl_simple.rs` — `.map_err(tmpfile_werr)` passes by value.
#[allow(clippy::needless_pass_by_value)] // .map_err(tmpfile_werr) passes by value; closure is uglier
fn tmpfile_werr(e: std::io::Error) -> CmdError {
    CmdError::Io {
        path: PathBuf::from("<tmpfile>"),
        err: e,
    }
}

// The line tokenizer — instance #7.

/// Parse a config-file line into `(key, val)`.
///
/// Differences from `join::split_var` (instance #6):
/// - Input has a trailing `\n` (file lines via `split_inclusive`);
///   we `rstrip` the value.
/// - We return `None` for blank lines AND for empty-key lines.
///
/// Why not call `join::split_var` then trim: the rstrip set is
/// `\t\r\n `. `split_var`'s caller already stripped its newlines;
/// ours hasn't. Different post-conditions.
///
/// PEM blocks: a `-----BEGIN PUBLIC KEY-----` line tokenizes as
/// `key = "-----BEGIN"`, `val = "PUBLIC KEY-----"`. It won't match
/// any variable name, so it falls through to copy-verbatim. We
/// inherit upstream's behavior — `tinc set -----BEGIN something`
/// would do something weird, but so would upstream.
fn split_line(line: &str) -> Option<(&str, &str)> {
    // ─── rstrip first: \t\r\n and space
    // We do it on the *whole line* up front, then tokenize.
    // Upstream does it on bvalue after key extraction — equivalent,
    // since the key portion never has trailing whitespace anyway
    // (the stop set IS whitespace).
    let trimmed = line.trim_end_matches(['\t', '\r', '\n', ' ']);

    // ─── Same key-end finding as parse_var_expr
    let key_end = trimmed.find(['\t', ' ', '=']).unwrap_or(trimmed.len());
    let key = &trimmed[..key_end];
    if key.is_empty() {
        return None;
    }

    let rest = &trimmed[key_end..];
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let val = rest.trim_start_matches([' ', '\t']);

    Some((key, val))
}

// Top-level: glue stages 1+2+3, handle the Port special case,
// fire opportunistic reload.

/// Result of a full `cmd_config` invocation. The binary turns this
/// into stdout/stderr/exit-code. Tests assert on the structure.
#[derive(Debug)]
pub enum ConfigOutput {
    /// `Get` found these values. Binary prints one per line.
    Got(GetResult),
    /// `Set`/`Add`/`Del` succeeded. Binary fires reload if `changed`.
    Edited(EditResult),
}

/// `cmd_config` end-to-end.
///
/// `joined` is the rejoined argv tail — `args.join(" ")`. Upstream
/// does the joining itself (`strncat` loop); we push that to the
/// binary adapter so this function gets one string and the test
/// surface is simpler.
///
/// The opportunistic reload (`connect_tincd(false)`) is *not* here —
/// that's a binary concern. This function is fs-only. The binary
/// calls `ctl_simple::reload` after `Edited` returns.
///
/// # Errors
/// Validation failure (unknown var without force, etc.), file
/// missing, write error, `Del` matched nothing.
///
/// # `get Port` special case
///
/// If you ask for `Port` and the daemon is running, return the
/// *runtime* port from the pidfile instead of the configured one.
/// `Port = 0` in config → daemon picks a free port → pidfile has
/// the truth. We replicate but as best-effort: if `Pidfile::read`
/// succeeds, return that port; else fall back to scanning the
/// config like any other var. Upstream *exits early* on pidfile
/// success without falling back, which means a stale pidfile
/// (daemon crashed, file lingers) gives a stale port. We inherit
/// that — it's what users expect.
///
/// `paths` must have `resolve_runtime` called for the pidfile
/// path to be available. The binary's `needs_daemon` flag is `true`
/// for `config`/`get`/`set`/`add`/`del` for this reason — even
/// though they're 99% filesystem, the Port-from-pidfile and the
/// post-edit reload both need the runtime paths.
pub fn run(
    paths: &Paths,
    raw_action: Action,
    joined: &str,
    force: bool,
) -> Result<(ConfigOutput, Vec<Warning>), CmdError> {
    // ─── Stage 1: parse the var expression
    let (explicit_node, var, value) = parse_var_expr(joined)?;

    // ─── Port-from-pidfile special case
    // Condition: GET, var is Port (case-insens), no explicit node
    // (checked before any node resolution). We additionally check
    // `value.is_empty()` — upstream's GET→SET coercion (when value
    // is present) runs first, so by the time the Port check runs
    // it's already been coerced. The `is_empty()` here is redundant
    // but kept for clarity.
    if raw_action == Action::Get
        && value.is_empty()
        && explicit_node.is_none()
        && var.eq_ignore_ascii_case("Port")
    {
        // resolve_runtime must have run for pidfile() to be
        // populated. If the binary forgot (needs_daemon: false on
        // a config command), this panics, which is correct — it's
        // a binary bug, not user error.
        let pidfile_path = paths.pidfile();
        if let Ok(pf) = crate::ctl::Pidfile::read(pidfile_path) {
            // Return early with the pidfile's port. The `Got`
            // wrapper makes the binary print it the same way as any
            // other get.
            return Ok((ConfigOutput::Got(vec![pf.port]), Vec::new()));
        }
        // Upstream prints a stderr warning here. We swallow it — if
        // the pidfile's missing, the daemon's down and the
        // configured port IS the truth. The warning is noise. Minor
        // deviation, documented.
    }

    // ─── Stage 2: validate, resolve node, coerce action
    let (intent, mut warnings) = build_intent(paths, raw_action, explicit_node, var, value, force)?;

    // ─── Figure out which file
    let target = match &intent.node {
        Some(node) => paths.hosts_dir().join(node),
        None => paths.tinc_conf(),
    };

    // ─── Stage 3: walk the file
    match intent.action {
        Action::Get => {
            let values = run_get(&target, &intent.variable)?;
            // Empty result → error.
            if values.is_empty() {
                return Err(CmdError::BadInput(
                    "No matching configuration variables found.".into(),
                ));
            }
            Ok((ConfigOutput::Got(values), warnings))
        }
        Action::Set | Action::Add | Action::Del => {
            let result = run_edit(&target, &intent)?;
            // Merge walk-warnings (Removing) into validation
            // warnings. Order: validation first (they're pre-walk).
            // Not observable but consistent.
            warnings.extend(result.warnings);
            Ok((
                ConfigOutput::Edited(EditResult {
                    changed: result.changed,
                    warnings: Vec::new(), // moved into outer
                }),
                warnings,
            ))
        }
    }
}

// Tests

#[cfg(test)]
mod tests;
