//! `cmd_config` — `tinc get`/`set`/`add`/`del`. The config-editing CLI.
//!
//! C: `tincctl.c:1774-2138`, ~365 lines. The function is dense
//! enough that the C author marked it with both a NOLINT *and* a
//! 4096-byte stack buffer pair. It's the kind of function that does
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
//! ## Action coercions (the C's `argv++, argc--` jungle)
//!
//! Three places where the action you asked for isn't the one you get:
//!
//! 1. `get VAR VALUE` → `set VAR VALUE`. Line 1846. Probably a footgun
//!    but it's C behavior; replicating it would surprise nobody who
//!    types `tinc get Port` and adding `655` would surprise nobody
//!    who *intended* set. Kept.
//! 2. `add VAR VALUE` where VAR isn't `MULTIPLE` → `set` + warning.
//!    Line 1918. `tinc add Port 655` doesn't add a *second* Port
//!    line; it replaces. The warning fires if a value is being
//!    replaced (`warnonremove`).
//! 3. `set VAR VALUE` where VAR *is* `MULTIPLE` → `set` + warning.
//!    Line 1921. `tinc set Subnet 10.0.0.0/24` will delete every
//!    other Subnet line. You probably wanted `add`. Warning, not
//!    error — sometimes you do want a single subnet.
//!
//! ## What we drop / tighten
//!
//! - Windows `remove(filename)` before `rename`: dropped. Unix-only.
//! - `.config.tmp` cleanup on error paths. C leaves it on most error
//!   returns (e.g. `tincctl.c:2046`). `TmpGuard` ensures it goes.
//! - No 4096-byte line truncation. C `fgets` silently truncates and
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

#![allow(clippy::doc_markdown)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tinc_conf::vars::{self, VarFlags};

use super::{CmdError, exchange, io_err};
use crate::names::{self, Paths};

// Action enum — GET/SET/ADD/DEL after argv normalization.

/// What to do. C `tincctl.c:1784`: `typedef enum { GET, DEL, SET,
/// ADD } action_t`. We add `Unset` for the pre-dispatch state where
/// `get` defaults to `Get` but might become `Set` if a value is
/// given (the action-coercion at line 1846).
///
/// Why not a separate `Action::Get` vs `Action::GetOrSet`: the C
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
/// `hosts/n`. The C threads `node` through as `char*` and checks
/// it at the end; we resolve up-front.
#[derive(Debug)]
pub struct Intent {
    /// What to do. After all coercions (get-with-value → set,
    /// add-on-single → set).
    pub action: Action,
    /// Canonical-case variable name. `port` in argv → `Port` here.
    /// C `tincctl.c:1864`: `variable = (char *)variables[i].name`.
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

/// Warnings the validation layer emits to stderr. The C does
/// `fprintf(stderr, ...)` inline; we collect, the binary prints.
/// Tests assert on the vec.
///
/// Why an enum and not just `Vec<String>`: tests want to assert
/// "an obsolete-var warning fired", not "a string containing
/// 'obsolete' was emitted". Same `matches!` pattern as fsck's
/// `Finding`.
#[derive(Debug)]
pub enum Warning {
    /// `--force` set on an `OBSOLETE` var. C: `"Warning: %s is an
    /// obsolete variable!"`.
    Obsolete(String),
    /// `--force` set on a `node.VAR` write where VAR isn't `HOST`.
    /// C: `"Warning: %s is not a host configuration variable!"`.
    NotHostVar(String),
    /// `--force` or get/del on an unknown var. C: `"Warning: %s
    /// is not a known configuration variable!"`.
    Unknown(String),
    /// File walk: `set` is about to replace `<var> = <oldval>` with
    /// `<var> = <newval>`. C `tincctl.c:2034`: `"Warning: removing
    /// %s = %s\n"`. Emitted once per replaced line.
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
                // C uses `=` with single space on both sides. The
                // file might have `Port=655` or `Port  =  655`; the
                // warning normalizes. (Minor info loss, but the C
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
/// C `tincctl.c:1812-1838`. Same `strcspn`/`strspn` tokenizer that
/// appears in `conf.c`, `invitation.c`, etc. — the SEVENTH instance.
/// See module doc for why we don't unify them.
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
/// error (`tincctl.c:1835`: `"No variable given."`).
///
/// # Errors
/// `var` is empty (e.g. input is `".Port"` or `"= 655"` or `""`).
fn parse_var_expr(joined: &str) -> Result<(Option<&str>, &str, &str), CmdError> {
    // ─── Find end of key: first \t, space, or =
    // Same `find` set as `split_var` in join.rs. The C `strcspn` is
    // `strcspn(line, "\t =")` — those three chars exactly.
    let key_end = joined.find(['\t', ' ', '=']).unwrap_or(joined.len());
    let key = &joined[..key_end];

    // ─── Walk past separator to find value
    // C: `value += strspn(value, "\t ");
    //     if(*value == '=') { value++; value += strspn(value, "\t "); }`
    let rest = &joined[key_end..];
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let val = rest.trim_start_matches([' ', '\t']);

    // ─── Split key on '.' for node.var syntax
    // C `tincctl.c:1827`: `variable = strchr(line, '.')`. The `.`
    // doesn't appear in any var name (verified: `vars.rs` table is
    // alnum-only) so `find('.')` is unambiguous.
    let (node, var) = match key.find('.') {
        Some(dot) => (Some(&key[..dot]), &key[dot + 1..]),
        None => (None, key),
    };

    // ─── Empty var → error. C `if(!*variable)`
    // `alice.` → empty var. `.` alone → empty node AND empty var,
    // but the var check fires first. The C doesn't separately
    // validate the node here (it `check_id`'s later).
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
/// action coercions. C `tincctl.c:1856-1963`.
///
/// `paths` is needed because non-HOST vars on a missing-node
/// expression resolve to `hosts/$(get_my_name)`, which reads
/// `tinc.conf`. The C calls `get_my_name(true)` inline.
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
/// `tincctl.c:1866-1878`: when `variable == "Subnet"` and a value
/// is given, the C parses it with `str2net` + `subnetcheck` and
/// rejects malformed/non-canonical subnets early. We do the same
/// via `tinc_proto::Subnet`. This is the *one* case where the
/// `variables[]` table isn't enough — Subnet is the only var with
/// a validated value format that the CLI checks. (The daemon
/// validates everything via `read_config_file`, but `cmd_config`
/// writes blindly otherwise.)
// Too many lines: this function is the C's big lookup-loop body
// plus all surrounding policy. Splitting it would mean threading
// six locals (action, node, found, var, warn, force) through
// helpers. The C is 110 lines for the same span; we're at par.
#[allow(clippy::too_many_lines)]
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
    // C `tincctl.c:1846`: `if(action == GET && *value) action = SET`.
    // Happens BEFORE the table lookup — `tinc get Port 655` becomes
    // a `set` regardless of Port's flags. So we do it here.
    let mut action = if raw_action == Action::Get && !value.is_empty() {
        Action::Set
    } else {
        raw_action
    };

    // ─── set/add need a value
    // C `tincctl.c:1840`: `if((action == SET || action == ADD) &&
    // !*value)`. Check is BEFORE table lookup in C — we keep that
    // ordering so `tinc set garbagename` says "no value" not
    // "unknown variable".
    if matches!(action, Action::Set | Action::Add) && value.is_empty() {
        return Err(CmdError::BadInput("No value for variable given.".into()));
    }

    // ─── Look up in the variables table
    // C: linear scan of `variables[]`, `strcasecmp` match. We have
    // `vars::lookup` which does the same. The table is ~80 entries;
    // O(n) is fine.
    let found = vars::lookup(var);

    // ─── Subnet special case: validate value early
    // C `tincctl.c:1866-1878`. The check is inside the table-scan
    // loop body (after `found = true`), so it only fires if the var
    // is known AND named Subnet. The C `strcasecmp` is case-insensitive
    // so it validates regardless of user casing; we get the same via
    // `lookup` (case-insensitive) + checking the canonical table name.
    if let Some(v) = found {
        if v.name == "Subnet" && !value.is_empty() {
            validate_subnet(value)?;
        }
    }

    // ─── Canonical name from the table
    // C `tincctl.c:1864`: `variable = (char *)variables[i].name`.
    // The cast-away-const is C being C; we just take a `&'static str`.
    // If unknown, the user's casing survives (`strdup`-equivalent).
    let canonical: String = found.map_or_else(|| var.to_owned(), |v| v.name.to_owned());

    // ─── Obsolete check
    // C `tincctl.c:1883-1890`. Only fires for set/add — `get`
    // and `del` on an obsolete var are fine (you might be cleaning
    // up an old config).
    if let Some(v) = found {
        if v.flags.contains(VarFlags::OBSOLETE) && matches!(action, Action::Set | Action::Add) {
            if force {
                warnings.push(Warning::Obsolete(canonical.clone()));
            } else {
                return Err(CmdError::BadInput(format!(
                    "{canonical} is an obsolete variable! Use --force to use it anyway."
                )));
            }
        }
    }

    // ─── Server-var-in-hostfile check
    // C `tincctl.c:1893-1900`. `node.VAR` where VAR isn't HOST.
    // `tinc set alice.DeviceType tap` is suspicious — DeviceType is
    // a server-only var, why are you putting it in alice's host file?
    // Again only set/add — reading or deleting one is fine (might be
    // cleaning up after a previous --force).
    let mut node: Option<String> = explicit_node.map(str::to_owned);
    if let (Some(_), Some(v)) = (&node, found) {
        if !v.flags.contains(VarFlags::HOST) && matches!(action, Action::Set | Action::Add) {
            if force {
                warnings.push(Warning::NotHostVar(canonical.clone()));
            } else {
                return Err(CmdError::BadInput(format!(
                    "{canonical} is not a host configuration variable! Use --force to use it anyway."
                )));
            }
        }
    }

    // ─── HOST-only var with no explicit node → my host file
    // C `tincctl.c:1904-1910`. `tinc set Subnet 10.0.0.0/24` —
    // Subnet is HOST-only, no `node.` prefix, so where does it go?
    // C: `node = get_my_name(true)`. Reads tinc.conf, finds `Name =`,
    // returns it. Our `exchange::get_my_name` does the same.
    //
    // The C condition is `!node && !(type & VAR_SERVER)` — note
    // it's NOT `type & VAR_HOST`. The dual-tagged vars (e.g.
    // `Port`, both SERVER and HOST) take the SERVER path here →
    // they go in tinc.conf. Single-HOST-only goes in hosts/$me.
    if node.is_none() {
        if let Some(v) = found {
            if !v.flags.contains(VarFlags::SERVER) {
                // get_my_name's error already says "Name not found
                // in tinc.conf"; we don't wrap.
                node = Some(exchange::get_my_name(paths)?);
            }
        }
        // If not found AND no explicit node: tinc.conf. The C falls
        // through to `else { snprintf(filename, "%s", tinc_conf); }`
        // (`tincctl.c:1963`). Unknown vars go in the server config
        // unless you say otherwise.
    }

    // ─── Action coercion: add on non-MULTIPLE → set
    // C `tincctl.c:1917-1922`. The two `warnonremove` cases.
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
    // Unknown var: no coercion. `add` stays `add`. The C only
    // coerces inside the `for` loop body; unknown breaks early.

    // ─── check_id on node
    // C `tincctl.c:1925-1933`. The `if(node != line) free(node)`
    // is C lifetime juggling — node is either a pointer into `line`
    // (the explicit `alice.` case) or a `strdup` from `get_my_name`.
    // We don't have that problem; just check.
    if let Some(n) = &node {
        if !names::check_id(n) {
            return Err(CmdError::BadInput("Invalid name for node.".into()));
        }
    }

    // ─── Unknown var
    // C `tincctl.c:1935-1946`. Three-way: get/del → warning only,
    // set/add without force → error, set/add with force → warning.
    // The warning's `:` placement differs between the two C messages
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

/// Subnet value validation. C `tincctl.c:1866-1878`.
///
/// Splits into a separate function because it's the one place
/// `cmd_config` reaches into `tinc-proto`. The dep is justified
/// (see Cargo.toml comment) but isolating it makes the boundary
/// visible.
fn validate_subnet(value: &str) -> Result<(), CmdError> {
    use std::str::FromStr;
    let s = tinc_proto::Subnet::from_str(value).map_err(|_| {
        // C: `"Malformed subnet definition %s\n"`.
        CmdError::BadInput(format!("Malformed subnet definition {value}"))
    })?;
    // C: `if(!subnetcheck(s))`. Our `is_canonical` is the same
    // check (host bits must be zero).
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
    /// Open `<target>.config.tmp` for writing. C `tincctl.c:1972`:
    /// `snprintf(tmpfile, ..., "%s.config.tmp", filename)`.
    ///
    /// We `O_CREAT | O_TRUNC | O_WRONLY` at mode 0644 — same as
    /// the C `fopen("w")` under default umask. The target is a
    /// config file, not a key file; world-read is fine.
    fn open(target: &std::path::Path) -> Result<(Self, fs::File), CmdError> {
        // The `.config.tmp` suffix is exactly the C's. Can't use
        // `with_extension` — that'd replace `.conf`, not append.
        let mut tmp = target.as_os_str().to_owned();
        tmp.push(".config.tmp");
        let tmp = PathBuf::from(tmp);

        // C `fopen("w")`. Create-or-truncate. If a `.config.tmp`
        // is lying around from a crashed previous run, we just
        // overwrite it — exactly what the C does.
        //
        // C says "Could not open temporary file %s"; our `CmdError::Io`
        // says "Could not access <path>: <err>". The path identifies
        // the file (it ends in `.config.tmp`); the io::Error says
        // what went wrong. Slightly less specific than C, but the
        // actionable info (which file, what errno) is the same.
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
    /// C `tincctl.c:2128`: `rename(tmpfile, filename)`.
    ///
    /// `mem::take` on the path because we can't destructure a Drop
    /// type (E0509). After the take, `self.tmp` is empty PathBuf;
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
            // C doesn't do this — it just `return 1`s. We tighten.
            let _ = fs::remove_file(&tmp);
            // C: "Error renaming temporary file %s to configuration
            // file %s: %s". Our Io variant only carries one path; we
            // pick the target (it's the file the user asked about).
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
        // C doesn't unlink on error returns; we do. Harmless if
        // the file's already gone (`ENOENT` from `remove_file`
        // is silently dropped).
        let _ = fs::remove_file(&self.tmp);
    }
}

/// `Get`: scan the file, collect matching values.
///
/// Doesn't open a tmpfile — read-only. C `tincctl.c:1978`:
/// `if(action != GET) tf = fopen(tmpfile, "w")` — same gate.
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
        // `eq_ignore_ascii_case`: C `!strcasecmp(buf2, variable)`.
        // The variable is canonical-case from the table; the file
        // might say `port = 655`.
        if key.eq_ignore_ascii_case(variable) {
            found.push(val.to_owned());
        }
    }
    Ok(found)
}

/// `Set`/`Add`/`Del`: scan + transform + write tmpfile + rename.
///
/// The big one. C `tincctl.c:1991-2128`.
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
/// match exists, they append. C `tincctl.c:2088`.
// The C is ~140 lines for this span; we're at ~100. Structural
// fidelity (one walk, four arm-branches inside) is more readable
// than helper-per-action with a shared walk-iterator passed in.
// missing_panics_doc: see # Panics above; the unwrap is provably
// safe behind is_some_and but clippy can't see across statements.
#[allow(clippy::too_many_lines, clippy::missing_panics_doc)]
pub fn run_edit(path: &std::path::Path, intent: &Intent) -> Result<EditResult, CmdError> {
    debug_assert_ne!(intent.action, Action::Get, "use run_get for Get");

    // ─── Read whole file
    // C streams with `fgets` because of the 4096-byte stack buffer.
    // We can `read_to_string` — config files are kilobytes.
    let contents = fs::read_to_string(path).map_err(io_err(path))?;

    // ─── Open tmpfile (RAII; cleaned up on `?`)
    let (guard, mut tf) = TmpGuard::open(path)?;

    // ─── Walk lines
    // C state: `bool set = false; bool removed = false; bool
    // found = false;` (`found` is reused from the table-lookup
    // loop, here it means "ADD found a duplicate"). We use clearer
    // names.
    let mut already_set = false; // C `set` — Set wrote its one line
    let mut removed_any = false; // C `removed` — Del matched something
    let mut add_dup = false; // C `found` (reused) — Add found exact match
    let mut warnings = Vec::new();

    for line in contents.split_inclusive('\n') {
        // ─── Tokenize. None → not a key=val line (blank/comment/PEM)
        // The C handles this implicitly: empty key → strcasecmp
        // fails → fall through to copy-verbatim. We're explicit.
        let parsed = split_line(line);

        // ─── Match against our variable
        // The big four-arm dispatch. C `tincctl.c:2022-2057`.
        let matched = parsed
            .as_ref()
            .is_some_and(|(k, _)| k.eq_ignore_ascii_case(&intent.variable));

        if matched {
            // Safe: matched implies parsed.is_some().
            let (_, line_val) = parsed.unwrap();

            match intent.action {
                Action::Get => unreachable!("debug_assert above"),

                // ─── DEL: skip if value matches (or no filter)
                // C `tincctl.c:2027-2030`: `if(!*value ||
                // !strcasecmp(bvalue, value)) { removed = true;
                // continue; }`. The `continue` is the delete —
                // we just don't write the line.
                //
                // Value filter is case-insensitive. `tinc del
                // ConnectTo alice` matches `ConnectTo = Alice`.
                Action::Del => {
                    if intent.value.is_empty() || line_val.eq_ignore_ascii_case(&intent.value) {
                        removed_any = true;
                        continue; // ← the delete
                    }
                    // else: fall through to copy-verbatim. A Subnet
                    // line that didn't match the filter survives.
                }

                // ─── SET: replace first match, delete rest
                // C `tincctl.c:2031-2049`. The first-match-replaces,
                // subsequent-matches-delete behavior is what makes
                // SET on a MULTIPLE var dangerous (warnonremove).
                Action::Set => {
                    // Warning fires for *every* deleted/replaced line
                    // whose value differs from the new one. C
                    // `tincctl.c:2033`: `if(warnonremove &&
                    // strcasecmp(bvalue, value))`. Same value → no
                    // warning (you're setting it to what it already
                    // was; nothing's being lost).
                    if intent.warn_on_remove && !line_val.eq_ignore_ascii_case(&intent.value) {
                        warnings.push(Warning::Removing {
                            variable: intent.variable.clone(),
                            old_value: line_val.to_owned(),
                        });
                    }

                    if already_set {
                        // Second+ match: delete. C `tincctl.c:2039`:
                        // `if(set) continue;`.
                        continue;
                    }

                    // First match: replace in-place. C `tincctl.c:2042`:
                    // `fprintf(tf, "%s = %s\n", variable, value)`.
                    // Note: canonical case for the key, *not* the
                    // file's casing. `port = 655` in → `Port = 655`
                    // out. Intentional (the table is the canon).
                    writeln!(tf, "{} = {}", intent.variable, intent.value).map_err(tmpfile_werr)?;
                    already_set = true;
                    continue;
                }

                // ─── ADD: check for dup, fall through to copy
                // C `tincctl.c:2050-2054`. If exact match exists,
                // remember it (we'll skip the append at the end).
                // Either way, the existing line is preserved.
                Action::Add => {
                    if line_val.eq_ignore_ascii_case(&intent.value) {
                        add_dup = true;
                    }
                    // No continue! Fall through to copy.
                }
            }
        }

        // ─── Copy verbatim
        // C `tincctl.c:2059-2073`. Includes the "add newline if
        // missing" — last line might not have `\n`.
        //
        // `split_inclusive` gives us the trailing `\n` if it was
        // there, so we write `line` directly. The "add newline if
        // missing" check translates to: if `line` doesn't end with
        // `\n` (only true for the last line of a file with no
        // trailing newline), add one. C does the same check.
        tf.write_all(line.as_bytes()).map_err(tmpfile_werr)?;
        if !line.ends_with('\n') {
            tf.write_all(b"\n").map_err(tmpfile_werr)?;
        }
    }

    // ─── Append if needed
    // C `tincctl.c:2087-2093`. `Set` that matched nothing appends;
    // `Add` that found no dup appends.
    let needs_append = match intent.action {
        Action::Set => !already_set,
        Action::Add => !add_dup,
        Action::Del | Action::Get => false,
    };
    if needs_append {
        writeln!(tf, "{} = {}", intent.variable, intent.value).map_err(tmpfile_werr)?;
    }

    // ─── Flush + close. C `if(fclose(tf))`
    // Dropping `tf` flushes implicitly, but `sync_all` makes the
    // error visible. The C checks `fclose`'s return; we go further
    // (fsync). Config edits matter — `tinc set Port 655` followed
    // by an immediate daemon start should see the new port.
    tf.sync_all().map_err(tmpfile_werr)?;
    drop(tf);

    // ─── Del with nothing deleted → error
    // C `tincctl.c:2108-2112`. The condition is `(action == GET ||
    // action == DEL) && !removed` — but GET never reaches here
    // (we routed it to run_get). The C handles both because it's
    // one function; we don't have to.
    //
    // The C also `remove(tmpfile)` here; our TmpGuard::drop handles
    // that on the `?`.
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

/// Write error for the tmpfile. The C says "temporary file" in
/// every message (`tincctl.c:2046`, `:2062`, `:2070`, `:2091`);
/// `CmdError::Io` needs a path, so we use a sentinel one. The
/// user sees `Could not access <tmpfile>: <errno>` — fine, the
/// errno is what matters (probably ENOSPC).
///
/// `clippy::needless_pass_by_value`: same shape as `daemon_err` in
/// ctl_simple.rs — `.map_err(tmpfile_werr)` passes by value.
#[allow(clippy::needless_pass_by_value)]
fn tmpfile_werr(e: std::io::Error) -> CmdError {
    CmdError::Io {
        path: PathBuf::from("<tmpfile>"),
        err: e,
    }
}

// The line tokenizer — instance #7.

/// Parse a config-file line into `(key, val)`. C `tincctl.c:2002-2018`.
///
/// Differences from `join::split_var` (instance #6):
/// - Input has a trailing `\n` (file lines via `split_inclusive`);
///   we `rstrip` the value. C `tincctl.c:2016`: `rstrip(bvalue)`.
/// - We return `None` for blank lines AND for empty-key lines.
///   C handles blank implicitly (empty key → `strcasecmp` fails).
///
/// Why not call `join::split_var` then trim: the rstrip set is
/// `\t\r\n ` (C `tincctl.c:1589`). `split_var`'s caller already
/// stripped its newlines; ours hasn't. Different post-conditions.
///
/// PEM blocks: a `-----BEGIN PUBLIC KEY-----` line tokenizes as
/// `key = "-----BEGIN"`, `val = "PUBLIC KEY-----"`. It won't match
/// any variable name, so it falls through to copy-verbatim. The C
/// has the same behavior (no PEM-awareness in `cmd_config`). We
/// inherit that — `tinc set -----BEGIN something` would do
/// something weird, but so would the C.
fn split_line(line: &str) -> Option<(&str, &str)> {
    // ─── rstrip first: \t\r\n and space
    // C `tincctl.c:1589`: `while(len && strchr("\t\r\n ", value[len-1]))`.
    // We do it on the *whole line* up front, then tokenize. The C
    // does it on bvalue after key extraction — equivalent, since
    // the key portion never has trailing whitespace anyway (the
    // `strcspn` stop set IS whitespace).
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

/// `cmd_config` end-to-end. C `tincctl.c:1774-2138`.
///
/// `joined` is the rejoined argv tail — `args.join(" ")`. The C does
/// the joining itself (`strncat` loop, `tincctl.c:1805-1809`); we
/// push that to the binary adapter so this function gets one string
/// and the test surface is simpler.
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
/// C `tincctl.c:1850`: if you ask for `Port` and the daemon is
/// running, return the *runtime* port from the pidfile instead of
/// the configured one. `Port = 0` in config → daemon picks a free
/// port → pidfile has the truth. We replicate but as best-effort:
/// if `Pidfile::read` succeeds, return that port; else fall back
/// to scanning the config like any other var. The C *exits early*
/// on pidfile success without falling back, which means a stale
/// pidfile (daemon crashed, file lingers) gives a stale port. We
/// inherit that — the C's behavior is what users expect.
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
    // C `tincctl.c:1850`. Condition: GET, var is Port (case-insens),
    // no explicit node (the C checks before any node resolution).
    // We additionally check `value.is_empty()`. C order: line 1846
    // coerces GET→SET when value is present, line 1850 checks GET.
    // So the C already coerced before this point; the `is_empty()`
    // check here is redundant but kept for clarity.
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
            // Return early with the pidfile's port. C `tincctl.c:1765`:
            // `printf("%s\n", pidfile->port)`. The `Got` wrapper makes
            // the binary print it the same way as any other get.
            return Ok((ConfigOutput::Got(vec![pf.port]), Vec::new()));
        }
        // C `tincctl.c:1768`: `fprintf(stderr, "Could not get port
        // from the pidfile.\n")`. Then falls back to config scan.
        // We swallow the warning — if the pidfile's missing, the
        // daemon's down and the configured port IS the truth. The
        // C warning is noise. Minor deviation, documented.
    }

    // ─── Stage 2: validate, resolve node, coerce action
    let (intent, mut warnings) = build_intent(paths, raw_action, explicit_node, var, value, force)?;

    // ─── Figure out which file
    // C `tincctl.c:1949-1963`.
    let target = match &intent.node {
        Some(node) => paths.hosts_dir().join(node),
        None => paths.tinc_conf(),
    };

    // ─── Stage 3: walk the file
    match intent.action {
        Action::Get => {
            let values = run_get(&target, &intent.variable)?;
            // C `tincctl.c:2095-2101`: `if(found) return 0; else
            // ... return 1`. Empty result → error.
            if values.is_empty() {
                return Err(CmdError::BadInput(
                    "No matching configuration variables found.".into(),
                ));
            }
            Ok((ConfigOutput::Got(values), warnings))
        }
        Action::Set | Action::Add | Action::Del => {
            let result = run_edit(&target, &intent)?;
            // Merge walk-warnings (Removing) into validation warnings.
            // Order: validation first (those fired earlier in the C
            // too — they're pre-walk). Not observable but consistent.
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
mod tests {
    use super::*;
    use crate::names::PathsInput;

    // Stage 1: parse_var_expr — pure string munging, no fs

    #[test]
    fn parse_basic_var() {
        assert_eq!(parse_var_expr("Port").unwrap(), (None, "Port", ""));
    }

    #[test]
    fn parse_var_with_value() {
        assert_eq!(parse_var_expr("Port = 655").unwrap(), (None, "Port", "655"));
        // No-space-around-= is what the C accepts. `strcspn`
        // stop set includes `=`.
        assert_eq!(parse_var_expr("Port=655").unwrap(), (None, "Port", "655"));
        // Tab separator.
        assert_eq!(parse_var_expr("Port\t655").unwrap(), (None, "Port", "655"));
        // The argv-join produces space-joined — `tinc set Port 655`
        // → `"Port 655"`. No `=` in the joined string. The
        // tokenizer handles it: key ends at first space, val is
        // the rest after trimming.
        assert_eq!(parse_var_expr("Port 655").unwrap(), (None, "Port", "655"));
    }

    /// Multi-word value. `tinc set Name $HOST` shell-expanded to
    /// `tinc set Name = my host name` would join to `"Name = my host
    /// name"`. The C `strncat` loop preserves the spaces; `args.join(" ")`
    /// in the binary adapter does too.
    #[test]
    fn parse_multiword_value() {
        // Only the FIRST `\t /=` is the key boundary. Everything
        // after the val-start is value, spaces and all.
        assert_eq!(
            parse_var_expr("Name = host with spaces").unwrap(),
            (None, "Name", "host with spaces")
        );
    }

    #[test]
    fn parse_node_dot_var() {
        assert_eq!(
            parse_var_expr("alice.Port").unwrap(),
            (Some("alice"), "Port", "")
        );
        assert_eq!(
            parse_var_expr("alice.Port = 655").unwrap(),
            (Some("alice"), "Port", "655")
        );
        // No space around = AND a node prefix.
        assert_eq!(
            parse_var_expr("alice.Port=655").unwrap(),
            (Some("alice"), "Port", "655")
        );
    }

    /// `alice.` → empty var → error. C `if(!*variable)`.
    #[test]
    fn parse_empty_var_after_dot() {
        let e = parse_var_expr("alice.").unwrap_err();
        assert!(matches!(e, CmdError::BadInput(m) if m == "No variable given."));
    }

    /// `=655` → empty var. The `=` is in the stop set, so key_end=0.
    #[test]
    fn parse_empty_var_leading_equals() {
        let e = parse_var_expr("=655").unwrap_err();
        assert!(matches!(e, CmdError::BadInput(_)));
    }

    /// Value with embedded `=`. `tinc set Device = /dev/net/tun=weird`.
    /// The C splits on the FIRST `=`/ws — same here.
    #[test]
    fn parse_value_with_equals() {
        assert_eq!(
            parse_var_expr("Device = /dev/tun=x").unwrap(),
            (None, "Device", "/dev/tun=x")
        );
    }

    /// Dots in the value, not the key. `tinc set Address 10.0.0.1`.
    /// The `strchr(line, '.')` only scans the *key portion* (because
    /// `line[len] = '\0'` happens before the strchr). Our slice does
    /// the same — `key.find('.')`.
    #[test]
    fn parse_dots_in_value_not_node() {
        assert_eq!(
            parse_var_expr("Address = 10.0.0.1").unwrap(),
            (None, "Address", "10.0.0.1")
        );
        // But if there's no separator and the whole thing is the
        // key... `10.0.0.1` is treated as `node=10, var=0.0.1`.
        // Weird but it's what the C does (and `0.0.1` will fail
        // `vars::lookup` later).
        assert_eq!(
            parse_var_expr("10.0.0.1").unwrap(),
            (Some("10"), "0.0.1", "")
        );
    }

    // split_line — file-line tokenizer (instance #7)

    #[test]
    fn split_line_basic() {
        assert_eq!(split_line("Port = 655\n"), Some(("Port", "655")));
        assert_eq!(split_line("Port=655\n"), Some(("Port", "655")));
        assert_eq!(split_line("Port\t655\n"), Some(("Port", "655")));
    }

    /// rstrip set is `\t\r\n `. CRLF files (Windows-edited) have
    /// `\r\n` at line ends; the `\r` shouldn't end up in the value.
    #[test]
    fn split_line_crlf() {
        assert_eq!(split_line("Port = 655\r\n"), Some(("Port", "655")));
    }

    /// Trailing whitespace before the newline. C `rstrip` handles
    /// this; trim_end_matches with the same set does too.
    #[test]
    fn split_line_trailing_space() {
        assert_eq!(split_line("Port = 655   \n"), Some(("Port", "655")));
        assert_eq!(split_line("Port = 655\t\n"), Some(("Port", "655")));
    }

    /// Blank line → None. C: empty key → strcasecmp fails → falls
    /// through to copy-verbatim. We're explicit.
    #[test]
    fn split_line_blank() {
        assert_eq!(split_line("\n"), None);
        assert_eq!(split_line(""), None);
        assert_eq!(split_line("   \n"), None);
    }

    /// `#` comment lines. The C `cmd_config` does NOT have comment
    /// awareness — `#` is just a character. `# Port = 655` parses
    /// as `key = "#"`, `val = "Port = 655"`. The `#` won't match
    /// any variable, so it falls through to copy. Same behavior
    /// here.
    ///
    /// (`conf.c::parse_config_line` DOES have `#` handling, but
    /// `cmd_config` doesn't share that code. Intentional — `tinc
    /// set` operates on files-as-text, not files-as-config.)
    #[test]
    fn split_line_comment_passthrough() {
        // Tokenizes weirdly, but doesn't match anything → preserved.
        assert_eq!(split_line("# Port = 655\n"), Some(("#", "Port = 655")));
    }

    /// PEM line: `-----BEGIN PUBLIC KEY-----`. Tokenizes as
    /// `key="-----BEGIN"`, doesn't match anything, copies verbatim.
    /// Host files have these at the bottom; `tinc set Port 655`
    /// must preserve them.
    #[test]
    fn split_line_pem_passthrough() {
        let line = "-----BEGIN PUBLIC KEY-----\n";
        let (k, _) = split_line(line).unwrap();
        // Doesn't matter what k is, just that it isn't a var name.
        assert!(vars::lookup(k).is_none());
    }

    // Stage 2: build_intent — needs Paths for the get_my_name call

    /// Minimal confbase: tinc.conf with `Name = alice`, hosts/alice.
    /// Same setup helper as exchange.rs tests.
    fn setup(name: &str) -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let cb = dir.path().join("vpn");
        fs::create_dir_all(cb.join("hosts")).unwrap();
        fs::write(cb.join("tinc.conf"), format!("Name = {name}\n")).unwrap();
        fs::write(cb.join("hosts").join(name), "").unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(cb),
            ..Default::default()
        });
        (dir, paths)
    }

    #[test]
    fn intent_server_var_goes_to_tinc_conf() {
        let (_d, paths) = setup("alice");
        // Device is SERVER-only.
        let (intent, _) =
            build_intent(&paths, Action::Set, None, "Device", "/dev/tun", false).unwrap();
        assert_eq!(intent.node, None); // → tinc.conf
        assert_eq!(intent.variable, "Device"); // canonical (was already)
        assert_eq!(intent.action, Action::Set);
    }

    #[test]
    fn intent_host_var_goes_to_my_host_file() {
        let (_d, paths) = setup("alice");
        // Subnet is HOST-only (and MULTIPLE, but that's a different test).
        let (intent, _) =
            build_intent(&paths, Action::Add, None, "Subnet", "10.0.0.0/24", false).unwrap();
        // Resolved via get_my_name → "alice".
        assert_eq!(intent.node.as_deref(), Some("alice"));
    }

    /// Explicit `alice.Subnet` overrides the get_my_name resolution.
    #[test]
    fn intent_explicit_node_wins() {
        let (_d, paths) = setup("alice");
        let (intent, _) = build_intent(
            &paths,
            Action::Add,
            Some("bob"),
            "Subnet",
            "10.0.0.0/24",
            false,
        )
        .unwrap();
        assert_eq!(intent.node.as_deref(), Some("bob"));
    }

    /// Port is dual-tagged (SERVER | HOST). The C condition
    /// `!(type & VAR_SERVER)` means dual-tagged vars take the
    /// SERVER path → tinc.conf, not hosts/$me. `tincctl.c:1904`.
    #[test]
    fn intent_dual_tagged_goes_to_tinc_conf() {
        let (_d, paths) = setup("alice");
        // Precondition: Cipher really is S|H. If the table changes,
        // this test's premise breaks and someone re-reads the C.
        // (Port is HOST-only — `tincctl.c:1751`: `{"Port", VAR_HOST}`.
        // First version of this test wrongly assumed Port was dual.
        // `tinc set Port 655` writes to hosts/$me, not tinc.conf.
        // The pidfile-reading `tinc get Port` is precisely BECAUSE
        // the configured Port lives in the host file but the runtime
        // port is global state.)
        let v = vars::lookup("Cipher").unwrap();
        assert!(v.flags.contains(VarFlags::SERVER));
        assert!(v.flags.contains(VarFlags::HOST));

        let (intent, _) =
            build_intent(&paths, Action::Set, None, "Cipher", "aes-256-gcm", false).unwrap();
        // SERVER bit set → tinc.conf, even though HOST is also set.
        assert_eq!(intent.node, None);
    }

    /// And the contrapositive: Port is HOST-only → hosts/$me.
    /// Separate test so the dual-tagged one above can't accidentally
    /// pass for the wrong reason.
    #[test]
    fn intent_port_is_host_only() {
        let (_d, paths) = setup("alice");
        let v = vars::lookup("Port").unwrap();
        assert!(!v.flags.contains(VarFlags::SERVER));
        assert!(v.flags.contains(VarFlags::HOST));

        let (intent, _) = build_intent(&paths, Action::Set, None, "Port", "655", false).unwrap();
        // HOST-only → hosts/alice via get_my_name.
        assert_eq!(intent.node.as_deref(), Some("alice"));
    }

    /// Canonicalization: `port` → `Port`. C `tincctl.c:1864`.
    #[test]
    fn intent_canonicalizes_var_name() {
        let (_d, paths) = setup("alice");
        let (intent, _) = build_intent(&paths, Action::Set, None, "port", "655", false).unwrap();
        assert_eq!(intent.variable, "Port");
    }

    /// `add` on non-MULTIPLE → `set` + warnonremove. `tincctl.c:1918`.
    #[test]
    fn intent_add_on_single_becomes_set() {
        let (_d, paths) = setup("alice");
        // Port is not MULTIPLE.
        let (intent, _) = build_intent(&paths, Action::Add, None, "Port", "655", false).unwrap();
        assert_eq!(intent.action, Action::Set);
        assert!(intent.warn_on_remove);
    }

    /// `set` on MULTIPLE → still `set`, but warnonremove. `tincctl.c:1921`.
    #[test]
    fn intent_set_on_multiple_warns() {
        let (_d, paths) = setup("alice");
        // ConnectTo is SERVER | MULTIPLE.
        let (intent, _) =
            build_intent(&paths, Action::Set, None, "ConnectTo", "bob", false).unwrap();
        assert_eq!(intent.action, Action::Set); // unchanged
        assert!(intent.warn_on_remove);
    }

    /// `add` on MULTIPLE stays `add`. The intended use case.
    #[test]
    fn intent_add_on_multiple_stays_add() {
        let (_d, paths) = setup("alice");
        let (intent, _) =
            build_intent(&paths, Action::Add, None, "ConnectTo", "bob", false).unwrap();
        assert_eq!(intent.action, Action::Add);
        assert!(!intent.warn_on_remove);
    }

    /// `get` with a value → `set`. C `tincctl.c:1846`.
    #[test]
    fn intent_get_with_value_becomes_set() {
        let (_d, paths) = setup("alice");
        let (intent, _) = build_intent(&paths, Action::Get, None, "Port", "655", false).unwrap();
        assert_eq!(intent.action, Action::Set);
    }

    #[test]
    fn intent_set_without_value_fails() {
        let (_d, paths) = setup("alice");
        let e = build_intent(&paths, Action::Set, None, "Port", "", false).unwrap_err();
        assert!(matches!(e, CmdError::BadInput(m) if m == "No value for variable given."));
    }

    /// Unknown var without force → error. C `tincctl.c:1935`.
    #[test]
    fn intent_unknown_var_fails() {
        let (_d, paths) = setup("alice");
        let e = build_intent(&paths, Action::Set, None, "NoSuchVar", "x", false).unwrap_err();
        let CmdError::BadInput(m) = e else { panic!() };
        assert!(m.contains("not a known configuration variable"));
        assert!(m.contains("--force"));
    }

    /// Unknown var WITH force → warning, proceed. C `tincctl.c:1937`.
    #[test]
    fn intent_unknown_var_force_proceeds() {
        let (_d, paths) = setup("alice");
        let (intent, warns) =
            build_intent(&paths, Action::Set, None, "NoSuchVar", "x", true).unwrap();
        assert_eq!(intent.variable, "NoSuchVar"); // user's casing survives
        assert_eq!(intent.node, None); // unknown → tinc.conf
        assert_eq!(warns.len(), 1);
        assert!(matches!(&warns[0], Warning::Unknown(v) if v == "NoSuchVar"));
    }

    /// `get`/`del` on unknown var: warning but proceed (no force needed).
    /// C `tincctl.c:1937`: `if(force || action == GET || action == DEL)`.
    /// Reading or deleting something the table doesn't know about is
    /// safe — you're not adding cruft, you might be cleaning it up.
    #[test]
    fn intent_unknown_var_get_proceeds() {
        let (_d, paths) = setup("alice");
        let (intent, warns) =
            build_intent(&paths, Action::Get, None, "NoSuchVar", "", false).unwrap();
        assert_eq!(intent.action, Action::Get);
        assert!(matches!(&warns[0], Warning::Unknown(_)));
    }

    /// Obsolete var → error without force. Find one in the table.
    #[test]
    fn intent_obsolete_var_fails() {
        let (_d, paths) = setup("alice");
        // PrivateKey is OBSOLETE (the *file* var; the `PrivateKeyFile`
        // pointer-to-file is current). Check the table to be sure
        // this test isn't a false positive.
        let v = vars::lookup("PrivateKey").expect("PrivateKey is in the table");
        assert!(
            v.flags.contains(VarFlags::OBSOLETE),
            "test assumption: PrivateKey is obsolete"
        );

        let e = build_intent(&paths, Action::Set, None, "PrivateKey", "x", false).unwrap_err();
        let CmdError::BadInput(m) = e else { panic!() };
        assert!(m.contains("obsolete"));
    }

    /// Obsolete var on GET: fine. The check is set/add only.
    #[test]
    fn intent_obsolete_var_get_ok() {
        let (_d, paths) = setup("alice");
        let (intent, warns) =
            build_intent(&paths, Action::Get, None, "PrivateKey", "", false).unwrap();
        assert_eq!(intent.action, Action::Get);
        // No obsolete warning — the check doesn't fire for get.
        assert!(!warns.iter().any(|w| matches!(w, Warning::Obsolete(_))));
    }

    /// `node.SERVER_VAR` without force → error. C `tincctl.c:1893`.
    #[test]
    fn intent_server_var_in_hostfile_fails() {
        let (_d, paths) = setup("alice");
        // Device is SERVER-only.
        let e = build_intent(
            &paths,
            Action::Set,
            Some("bob"),
            "Device",
            "/dev/tun",
            false,
        )
        .unwrap_err();
        let CmdError::BadInput(m) = e else { panic!() };
        assert!(m.contains("not a host configuration variable"));
    }

    /// Explicit node fails check_id. C `tincctl.c:1925`.
    #[test]
    fn intent_bad_node_name() {
        let (_d, paths) = setup("alice");
        let e = build_intent(&paths, Action::Get, Some("bad/name"), "Port", "", false).unwrap_err();
        assert!(matches!(e, CmdError::BadInput(m) if m == "Invalid name for node."));
    }

    /// Subnet validation: malformed value rejected. C `tincctl.c:1870`.
    #[test]
    fn intent_subnet_malformed() {
        let (_d, paths) = setup("alice");
        let e =
            build_intent(&paths, Action::Add, None, "Subnet", "not-a-subnet", false).unwrap_err();
        let CmdError::BadInput(m) = e else { panic!() };
        assert!(m.contains("Malformed subnet definition"));
    }

    /// Subnet validation: non-canonical (host bits set). C
    /// `tincctl.c:1874`: `subnetcheck`.
    #[test]
    fn intent_subnet_non_canonical() {
        let (_d, paths) = setup("alice");
        // 10.0.0.1/24: the .1 is a host bit. Prefix says /24,
        // first 3 octets are network, .1 is in the host portion.
        let e =
            build_intent(&paths, Action::Add, None, "Subnet", "10.0.0.1/24", false).unwrap_err();
        let CmdError::BadInput(m) = e else { panic!() };
        assert!(m.contains("Network address and prefix length do not match"));
    }

    #[test]
    fn intent_subnet_valid() {
        let (_d, paths) = setup("alice");
        let (intent, _) =
            build_intent(&paths, Action::Add, None, "Subnet", "10.0.0.0/24", false).unwrap();
        assert_eq!(intent.value, "10.0.0.0/24");
    }

    // Stage 3: run_get — read-only file walk

    #[test]
    fn get_single_value() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "Name = alice\nPort = 655\n").unwrap();
        assert_eq!(run_get(&f, "Port").unwrap(), vec!["655"]);
    }

    #[test]
    fn get_multiple_values() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = bob\nConnectTo = carol\n").unwrap();
        assert_eq!(run_get(&f, "ConnectTo").unwrap(), vec!["bob", "carol"]);
    }

    /// Case-insensitive match. `port` in the file matches `Port`
    /// query. C `!strcasecmp(buf2, variable)`.
    #[test]
    fn get_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "port = 655\n").unwrap();
        assert_eq!(run_get(&f, "Port").unwrap(), vec!["655"]);
    }

    #[test]
    fn get_no_match_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "Name = alice\n").unwrap();
        assert!(run_get(&f, "Port").unwrap().is_empty());
        // The "no match → error" is in run(), not run_get().
    }

    #[test]
    fn get_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("nonexistent");
        let e = run_get(&f, "Port").unwrap_err();
        assert!(matches!(e, CmdError::Io { .. }));
    }

    // Stage 3: run_edit — the big one

    /// Helper: build an Intent without going through stage 2. Tests
    /// the file walk in isolation.
    fn intent(action: Action, var: &str, val: &str, warn: bool) -> Intent {
        Intent {
            action,
            variable: var.to_owned(),
            value: val.to_owned(),
            node: None, // run_edit doesn't look at node; caller picks the path
            warn_on_remove: warn,
        }
    }

    #[test]
    fn set_replaces_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "Name = alice\nPort = 655\nDevice = /dev/tun\n").unwrap();

        run_edit(&f, &intent(Action::Set, "Port", "1234", false)).unwrap();

        // The Port line is replaced *at the same position*. Name
        // and Device stay where they were. C `tincctl.c:2042`.
        assert_eq!(
            fs::read_to_string(&f).unwrap(),
            "Name = alice\nPort = 1234\nDevice = /dev/tun\n"
        );
    }

    /// SET when no match exists → append. C `tincctl.c:2087`.
    #[test]
    fn set_appends_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "Name = alice\n").unwrap();

        run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap();

        assert_eq!(
            fs::read_to_string(&f).unwrap(),
            "Name = alice\nPort = 655\n"
        );
    }

    /// SET on duplicate keys: first replaced, rest deleted. The
    /// `if(set) continue;` at `tincctl.c:2039`. This is what
    /// makes SET dangerous on MULTIPLE vars.
    #[test]
    fn set_collapses_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        // Weird config (Port shouldn't be dup, but a hand-edited
        // file might have it). C handles it; we do too.
        fs::write(&f, "Port = 1\nPort = 2\nPort = 3\n").unwrap();

        run_edit(&f, &intent(Action::Set, "Port", "999", false)).unwrap();

        // First replaced, second and third deleted.
        assert_eq!(fs::read_to_string(&f).unwrap(), "Port = 999\n");
    }

    /// SET with warnonremove: warning fires once per replaced line
    /// whose value DIFFERS. Same value → no warning.
    #[test]
    fn set_warnonremove() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = bob\nConnectTo = carol\nConnectTo = dave\n").unwrap();

        // SET on a MULTIPLE var: stage-2 would set warnonremove.
        // We construct directly with warn=true to test the walk.
        let result = run_edit(&f, &intent(Action::Set, "ConnectTo", "carol", true)).unwrap();

        // Three matches: bob (differs → warn), carol (same → no warn),
        // dave (differs → warn). C `tincctl.c:2033`: `if(warnonremove
        // && strcasecmp(bvalue, value))` — case-insensitive diff check.
        assert_eq!(result.warnings.len(), 2);
        assert!(matches!(
            &result.warnings[0],
            Warning::Removing { old_value, .. } if old_value == "bob"
        ));
        assert!(matches!(
            &result.warnings[1],
            Warning::Removing { old_value, .. } if old_value == "dave"
        ));

        assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = carol\n");
    }

    /// SET canonicalizes the key in the output. `port = 655` in,
    /// `Port = 1234` out. C `fprintf(tf, "%s = %s\n", variable, ...)`
    /// where `variable` was canonicalized at `tincctl.c:1864`.
    #[test]
    fn set_canonicalizes_key_case() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "port = 655\n").unwrap();

        // The `variable` we pass is already canonical (stage 2 did
        // that). The walk writes it as-is.
        run_edit(&f, &intent(Action::Set, "Port", "1234", false)).unwrap();

        assert_eq!(fs::read_to_string(&f).unwrap(), "Port = 1234\n");
    }

    #[test]
    fn add_appends() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = bob\n").unwrap();

        run_edit(&f, &intent(Action::Add, "ConnectTo", "carol", false)).unwrap();

        assert_eq!(
            fs::read_to_string(&f).unwrap(),
            "ConnectTo = bob\nConnectTo = carol\n"
        );
    }

    /// ADD when exact value already present → no-op. C
    /// `tincctl.c:2052`: `if(!strcasecmp(bvalue, value)) found = true`.
    #[test]
    fn add_dedup_noop() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = bob\n").unwrap();

        run_edit(&f, &intent(Action::Add, "ConnectTo", "bob", false)).unwrap();

        // File unchanged. (Well, rewritten via tmpfile → rename,
        // but bytes identical.)
        assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = bob\n");
    }

    /// ADD dedup is case-insensitive on the value. C `strcasecmp`.
    /// `tinc add ConnectTo Alice` after `ConnectTo = alice` is a
    /// no-op. Probably correct — node names are case-folded
    /// elsewhere too (`check_id` doesn't enforce case).
    #[test]
    fn add_dedup_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = alice\n").unwrap();

        run_edit(&f, &intent(Action::Add, "ConnectTo", "ALICE", false)).unwrap();

        // The existing line survives WITH ITS ORIGINAL CASE. ADD
        // doesn't normalize, it just doesn't append.
        assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = alice\n");
    }

    #[test]
    fn del_removes_all() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = bob\nName = x\nConnectTo = carol\n").unwrap();

        run_edit(&f, &intent(Action::Del, "ConnectTo", "", false)).unwrap();

        assert_eq!(fs::read_to_string(&f).unwrap(), "Name = x\n");
    }

    /// DEL with value filter: only matching lines removed.
    /// C `tincctl.c:2027`: `if(!*value || !strcasecmp(bvalue, value))`.
    #[test]
    fn del_filtered() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = bob\nConnectTo = carol\n").unwrap();

        run_edit(&f, &intent(Action::Del, "ConnectTo", "bob", false)).unwrap();

        assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = carol\n");
    }

    /// DEL that matches nothing → error. C `tincctl.c:2108`.
    #[test]
    fn del_nothing_fails() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "Name = alice\n").unwrap();

        let e = run_edit(&f, &intent(Action::Del, "ConnectTo", "", false)).unwrap_err();
        assert!(matches!(e, CmdError::BadInput(m) if m == "No configuration variables deleted."));

        // And the original file is untouched.
        assert_eq!(fs::read_to_string(&f).unwrap(), "Name = alice\n");
    }

    /// DEL filter with no match (var exists but value doesn't) → error.
    /// `tinc del ConnectTo nonexistent`.
    #[test]
    fn del_filter_no_match_fails() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = bob\n").unwrap();

        let e = run_edit(&f, &intent(Action::Del, "ConnectTo", "carol", false)).unwrap_err();
        assert!(matches!(e, CmdError::BadInput(_)));
        // Original survives.
        assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = bob\n");
    }

    /// Tmpfile is gone after a failed DEL. The C `tincctl.c:2110`
    /// does `remove(tmpfile)` here; we do it via TmpGuard::drop.
    #[test]
    fn tmpfile_cleaned_up_on_del_failure() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "Name = alice\n").unwrap();

        let _ = run_edit(&f, &intent(Action::Del, "Nonexistent", "", false));

        // No `.config.tmp` lying around.
        assert!(!dir.path().join("tinc.conf.config.tmp").exists());
    }

    /// File without trailing newline: edit must add one before any
    /// append. C `tincctl.c:2067`: `if(*buf1 && buf1[strlen(buf1)-1]
    /// != '\n')`. Otherwise you get `Name = alicePort = 655`.
    #[test]
    fn edit_adds_newline_before_append() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "Name = alice").unwrap(); // no trailing \n

        run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap();

        assert_eq!(
            fs::read_to_string(&f).unwrap(),
            "Name = alice\nPort = 655\n"
        );
    }

    /// PEM block at the end of a host file. `tinc set Port 655`
    /// must NOT mangle the base64 lines. The split_line tokenizer
    /// returns `Some((garbage, garbage))` for them but they don't
    /// match `Port`, so they copy verbatim.
    #[test]
    fn edit_preserves_pem() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("hosts_alice");
        let pem = "\
Port = 655
-----BEGIN ED25519 PUBLIC KEY-----
MCowBQYDK2VwAyEAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
-----END ED25519 PUBLIC KEY-----
";
        fs::write(&f, pem).unwrap();

        run_edit(&f, &intent(Action::Set, "Port", "1234", false)).unwrap();

        // PEM block byte-identical. Only the Port line changed.
        let after = fs::read_to_string(&f).unwrap();
        assert!(after.starts_with("Port = 1234\n"));
        assert!(after.contains("-----BEGIN ED25519 PUBLIC KEY-----\n"));
        assert!(after.contains("MCowBQYDK2VwAyEA"));
        assert!(after.contains("-----END ED25519 PUBLIC KEY-----\n"));
        // Exactly four lines — nothing got duplicated or eaten.
        assert_eq!(after.lines().count(), 4);
    }

    /// Comment lines preserved verbatim. The C doesn't parse `#`;
    /// they're just lines whose key is `#` and don't match.
    #[test]
    fn edit_preserves_comments() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "# this is alice's config\nName = alice\n").unwrap();

        run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap();

        let after = fs::read_to_string(&f).unwrap();
        assert!(after.starts_with("# this is alice's config\n"));
    }

    /// Edit on a file we can't read → error, no tmpfile created.
    #[test]
    fn edit_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("nonexistent");
        let e = run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap_err();
        assert!(matches!(e, CmdError::Io { .. }));
        // No `.config.tmp` — we never got that far.
        assert!(!dir.path().join("nonexistent.config.tmp").exists());
    }

    // run() — full pipeline

    /// `setup_full`: confbase with tinc.conf + hosts/alice + a
    /// resolved pidfile path (pointing nowhere real, so the
    /// Port-from-pidfile path falls back to config).
    fn setup_full(name: &str, conf_body: &str) -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let cb = dir.path().join("vpn");
        fs::create_dir_all(cb.join("hosts")).unwrap();
        fs::write(cb.join("tinc.conf"), format!("Name = {name}\n{conf_body}")).unwrap();
        fs::write(cb.join("hosts").join(name), "").unwrap();

        let input = PathsInput {
            confbase: Some(cb),
            // Pidfile that doesn't exist — Port-from-pidfile read
            // fails silently, falls back to config scan.
            pidfile: Some(dir.path().join("no.pid")),
            ..Default::default()
        };
        let mut paths = Paths::for_cli(&input);
        // The `get Port` path calls `paths.pidfile()`, which panics
        // if not resolved. Tests must resolve.
        paths.resolve_runtime(&input);
        (dir, paths)
    }

    #[test]
    fn run_full_get() {
        let (_d, paths) = setup_full("alice", "Device = /dev/tun\n");
        let (out, _) = run(&paths, Action::Get, "Device", false).unwrap();
        let ConfigOutput::Got(vals) = out else {
            panic!("expected Got")
        };
        assert_eq!(vals, vec!["/dev/tun"]);
    }

    #[test]
    fn run_full_get_not_found() {
        let (_d, paths) = setup_full("alice", "");
        let e = run(&paths, Action::Get, "Device", false).unwrap_err();
        assert!(
            matches!(e, CmdError::BadInput(m) if m == "No matching configuration variables found.")
        );
    }

    /// The full `tinc add Subnet 10.0.0.0/24` path: stage 2 routes
    /// to hosts/alice (Subnet is HOST-only), stage 3 appends.
    #[test]
    fn run_full_add_subnet_to_host_file() {
        let (d, paths) = setup_full("alice", "");
        run(&paths, Action::Add, "Subnet 10.0.0.0/24", false).unwrap();

        // Went to hosts/alice, not tinc.conf.
        let host = fs::read_to_string(d.path().join("vpn/hosts/alice")).unwrap();
        assert_eq!(host, "Subnet = 10.0.0.0/24\n");
        // tinc.conf untouched.
        let conf = fs::read_to_string(d.path().join("vpn/tinc.conf")).unwrap();
        assert_eq!(conf, "Name = alice\n");
    }

    /// `tinc set bob.Subnet 10.0.0.0/24` writes to hosts/bob even
    /// though we're alice. The explicit node prefix wins.
    #[test]
    fn run_full_explicit_node() {
        let (d, paths) = setup_full("alice", "");
        // hosts/bob must exist for the read to succeed. C: same
        // requirement (`fopen(filename, "r")` fails otherwise).
        fs::write(d.path().join("vpn/hosts/bob"), "").unwrap();

        run(&paths, Action::Set, "bob.Subnet 10.0.0.0/24", false).unwrap();

        let bob = fs::read_to_string(d.path().join("vpn/hosts/bob")).unwrap();
        assert_eq!(bob, "Subnet = 10.0.0.0/24\n");
    }

    /// `tinc get Port` with daemon running (pidfile exists): returns
    /// the *runtime* port from the pidfile, NOT the configured one.
    /// `Port = 0` is the use case — daemon picks a free port.
    #[test]
    fn run_get_port_from_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let cb = dir.path().join("vpn");
        fs::create_dir_all(cb.join("hosts")).unwrap();
        // Config says Port = 0.
        fs::write(cb.join("tinc.conf"), "Name = alice\nPort = 0\n").unwrap();
        fs::write(cb.join("hosts/alice"), "").unwrap();

        // Pidfile says the actual port is 47123.
        let pidfile = dir.path().join("tinc.pid");
        let cookie = "a".repeat(64);
        fs::write(&pidfile, format!("1 {cookie} 127.0.0.1 port 47123\n")).unwrap();

        let input = PathsInput {
            confbase: Some(cb),
            pidfile: Some(pidfile),
            ..Default::default()
        };
        let mut paths = Paths::for_cli(&input);
        paths.resolve_runtime(&input);

        let (out, _) = run(&paths, Action::Get, "Port", false).unwrap();
        let ConfigOutput::Got(vals) = out else {
            panic!()
        };
        // 47123 from the pidfile, NOT 0 from the config.
        assert_eq!(vals, vec!["47123"]);
    }

    /// `tinc get Port` with no daemon (pidfile missing): falls back
    /// to scanning hosts/$me (Port is HOST-only). C `tincctl.c:1768`
    /// would print a stderr warning here; we silently fall back
    /// (see module doc).
    #[test]
    fn run_get_port_fallback_to_config() {
        let (d, paths) = setup_full("alice", "");
        // Port is HOST-only → lives in hosts/alice, not tinc.conf.
        // setup_full creates an empty hosts/alice; overwrite.
        fs::write(d.path().join("vpn/hosts/alice"), "Port = 655\n").unwrap();

        // setup_full's pidfile points nowhere → read fails → fallback.
        let (out, _) = run(&paths, Action::Get, "Port", false).unwrap();
        let ConfigOutput::Got(vals) = out else {
            panic!()
        };
        assert_eq!(vals, vec!["655"]);
    }

    /// `tinc get alice.Port` does NOT take the pidfile path —
    /// explicit node means "the configured port for that host file",
    /// not "the running daemon's port". C `tincctl.c:1850` checks
    /// before any node resolution; the explicit node short-circuits.
    #[test]
    fn run_get_port_explicit_node_skips_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let cb = dir.path().join("vpn");
        fs::create_dir_all(cb.join("hosts")).unwrap();
        fs::write(cb.join("tinc.conf"), "Name = alice\n").unwrap();
        // hosts/alice has Port = 1234. The pidfile would say 47123
        // but we should never read it for an explicit-node get.
        fs::write(cb.join("hosts/alice"), "Port = 1234\n").unwrap();

        let pidfile = dir.path().join("tinc.pid");
        let cookie = "a".repeat(64);
        fs::write(&pidfile, format!("1 {cookie} 127.0.0.1 port 47123\n")).unwrap();

        let input = PathsInput {
            confbase: Some(cb),
            pidfile: Some(pidfile),
            ..Default::default()
        };
        let mut paths = Paths::for_cli(&input);
        paths.resolve_runtime(&input);

        // `alice.Port` — explicit node prefix.
        let (out, _) = run(&paths, Action::Get, "alice.Port", false).unwrap();
        let ConfigOutput::Got(vals) = out else {
            panic!()
        };
        // 1234 from hosts/alice, NOT 47123 from the pidfile.
        // Proves the `explicit_node.is_none()` guard in run().
        assert_eq!(vals, vec!["1234"]);
    }

    /// End-to-end: `tinc get Port 655` is the same as `tinc set
    /// Port 655`. The get-with-value coercion. C `tincctl.c:1846`.
    #[test]
    fn run_get_with_value_is_set() {
        let (d, paths) = setup_full("alice", "");
        run(&paths, Action::Get, "Device /dev/tun", false).unwrap();

        // Device was set, not gotten.
        let conf = fs::read_to_string(d.path().join("vpn/tinc.conf")).unwrap();
        assert!(conf.contains("Device = /dev/tun\n"));
    }

    // Compatibility tests — reading the C, not the impl.
    //
    // Each of these is derived from a specific C line and asserts a
    // behavior that would be easy to get subtly wrong. The test
    // name says what; the body comment says where in the C.

    /// `tincctl.c:2033`: warnonremove uses `strcasecmp` — the
    /// "same value, no warning" check is case-insensitive. Setting
    /// `ConnectTo = Alice` over `ConnectTo = alice` is a no-warn
    /// (you're not losing anything; it's the same node).
    #[test]
    fn c_warnonremove_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tinc.conf");
        fs::write(&f, "ConnectTo = alice\n").unwrap();

        let result = run_edit(&f, &intent(Action::Set, "ConnectTo", "ALICE", true)).unwrap();

        // Value differs only in case → no warning.
        assert!(result.warnings.is_empty());
    }

    /// `tincctl.c:1846` ordering: get→set coercion happens BEFORE
    /// `read_actual_port`. So `tinc get Port 655` does NOT read
    /// the pidfile — by the time we'd check, action is already SET.
    /// (Our impl checks `value.is_empty()` separately, which gives
    /// the same result. This test pins that they're equivalent.)
    #[test]
    fn c_get_port_with_value_skips_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let cb = dir.path().join("vpn");
        fs::create_dir_all(cb.join("hosts")).unwrap();
        fs::write(cb.join("tinc.conf"), "Name = alice\n").unwrap();
        fs::write(cb.join("hosts/alice"), "").unwrap();

        // Pidfile is BROKEN — if run() reads it, parse fails. If
        // run() correctly skips (because value is non-empty), we
        // never touch it.
        let pidfile = dir.path().join("tinc.pid");
        fs::write(&pidfile, "garbage\n").unwrap();

        let input = PathsInput {
            confbase: Some(cb),
            pidfile: Some(pidfile),
            ..Default::default()
        };
        let mut paths = Paths::for_cli(&input);
        paths.resolve_runtime(&input);

        // `get Port 655` → set. If this tried to read the broken
        // pidfile we'd... actually fall back silently. So we need
        // a positive assertion: the SET happened.
        // Port is HOST-only → the set goes to hosts/alice.
        run(&paths, Action::Get, "Port 655", false).unwrap();
        let host = fs::read_to_string(paths.hosts_dir().join("alice")).unwrap();
        assert!(host.contains("Port = 655\n"));
    }

    /// `tincctl.c:1909`: the `!node && !(type & VAR_SERVER)`
    /// condition uses NOT-SERVER, not HAS-HOST. A var with NEITHER
    /// flag (which doesn't exist in the real table, but the logic
    /// admits it) would resolve to hosts/$me. Only SERVER →
    /// tinc.conf. The dual-tagged test above covers HAS-BOTH; this
    /// covers the symmetry.
    ///
    /// We can't test with a real var (every var has SERVER or HOST),
    /// but we CAN check that the test's understanding of the
    /// condition is correct by reading the table: every var lacking
    /// SERVER must have HOST. (If that ever changes, this test
    /// breaks and someone re-reads the C.)
    #[test]
    fn c_every_nonserver_var_is_host() {
        // Trip-wire on the variables table. The build_intent logic
        // assumes !SERVER ⇒ must resolve to a host file via
        // get_my_name. If a var were neither SERVER nor HOST, that
        // resolution would still happen but the var wouldn't make
        // sense in a host file. Assert no such var exists.
        for v in vars::VARS {
            assert!(
                v.flags.contains(VarFlags::SERVER) || v.flags.contains(VarFlags::HOST),
                "{} has neither SERVER nor HOST; build_intent's !SERVER\
                 ⇒ hosts/$me assumption breaks",
                v.name
            );
        }
    }
}
