//! `tinc export`/`import`/`export-all`/`exchange`/`exchange-all`.
//! C reference: `tincctl.c:2474-2655`.
//!
//! ## What this is for
//!
//! Two tinc nodes that want to talk to each other need to swap host
//! files. Alice's `hosts/alice` (her public key + Subnets + Address)
//! goes to Bob's `hosts/alice`, and vice versa. This is the
//! out-of-band step before any wire bytes flow.
//!
//! `export` reads `hosts/$(our name)`, prepends `Name = X`, writes to
//! stdout. `import` reads that blob and writes `hosts/NAME`.
//! `export-all` does every host with a separator. `exchange` is
//! `export | (netcat/ssh) | import`, full duplex.
//!
//! ## The blob format
//!
//! ```text
//! Name = alice
//! Address = 192.0.2.1
//! Subnet = 10.0.1.0/24
//! Ed25519PublicKey = Pg2fEkaQ9lL...
//! -----BEGIN ED25519 PUBLIC KEY-----
//! ...
//! -----END ED25519 PUBLIC KEY-----
//!
//! #---------------------------------------------------------------#
//! Name = bob
//! Address = 192.0.2.2
//! ...
//! ```
//!
//! Things to notice:
//!
//! - **`Name =` is the framing.** Export *injects* it (it's not in
//!   `hosts/alice` — that file is *named* alice, the `Name =` line
//!   would be redundant). Import *parses* it to know what file to
//!   open. The host file's contents pass through unmodified except
//!   for any `Name =` lines, which export *strips* on the way out.
//!   So a host file that *does* contain `Name =` (unusual but legal)
//!   doesn't confuse import.
//!
//! - **The separator is exactly 65 chars.** `#` + 63 dashes + `#`.
//!   Import does an exact `strcmp` against the separator-with-newline
//!   — a 64-dash line is *not* a separator, it's content. Don't
//!   reformat this string.
//!
//! - **PEM blocks pass through opaque.** Export doesn't know or care
//!   about `-----BEGIN`. The host file is bytes; export ships bytes.
//!   `tinc-conf::parse_reader`'s PEM-stripping is a different
//!   concern (it's for *config lookup*, where you want
//!   `Ed25519PublicKey =` and not the armor body as a key=value).
//!
//! - **The blank line before the separator** (`\n#---..#\n`) is
//!   consumed by import as part of the previous host's content. C
//!   does this too; harmless but a "fix" would break round-trip.

#![allow(clippy::doc_markdown)]

use std::fs;
use std::io::{BufRead, BufWriter, Write};

use crate::cmd::{CmdError, io_err};
use crate::names::{self, Paths, check_id};

/// 65 chars: `#` + 63 dashes + `#`. C: `tincctl.c:2554` and `:2624`.
///
/// `import` matches against `SEPARATOR + "\n"` (the C `strcmp` includes
/// the `fgets` newline). We keep the newline separate so `export_all`
/// can write `\n` + SEPARATOR + `\n` (it wants a blank line *before*).
///
/// **Don't reformat.** rustfmt won't touch a `const &str`, but a
/// well-meaning human might "fix" the dash count. The C count is
/// exact; one off and import treats it as content.
const SEPARATOR: &str = "#---------------------------------------------------------------#";

// At 65, not 64 or 66. Belt and suspenders against the well-meaning
// human (or a search-and-replace that catches it).
const _: () = assert!(SEPARATOR.len() == 65);

/// `get_my_name` — read `Name = X` from `tinc.conf`, expand `$HOST`.
/// C: `tincctl.c:1596-1644`.
///
/// The C hand-rolls a config-line tokenizer (the same `strcspn` /
/// `strspn` dance as `conf.c::parse_config_line`, copy-pasted). We
/// have `tinc-conf` for that. Reads the whole file, looks up `Name`,
/// returns the first hit. Slightly more work than the C's stop-at-
/// first-match streaming scan, but `tinc.conf` is ~5 lines.
///
/// Returns the *post-expansion* name. `Name = $HOST` resolves.
///
/// `verbose` controls whether errors get a message — `cmd_export`
/// wants the message, `cmd_init`'s "is there already a tinc.conf"
/// pre-check (`tincctl.c:2318`) doesn't. We don't have that caller
/// yet but we will.
///
/// # Errors
/// - `tinc.conf` doesn't exist or can't be read
/// - No `Name =` line
/// - `replace_name` fails (bad env var, gethostname failed, fails `check_id`)
pub fn get_my_name(paths: &Paths) -> Result<String, CmdError> {
    let tinc_conf = paths.tinc_conf();

    // tinc-conf's `parse_file` already handles the line tokenization
    // (the strcspn/strspn dance), comment stripping, PEM skipping.
    // The C `get_my_name` reimplements all of that inline — it's a
    // ~40-line copy-paste of `parse_config_line`. We don't.
    let entries = tinc_conf::parse_file(&tinc_conf).map_err(|e| {
        // C: `Could not open %s: %s`. We get tinc-conf's slightly more
        // detailed message (it distinguishes parse error from I/O
        // error). Close enough — the path is what users grep for.
        CmdError::BadInput(format!("Could not open {}: {e}", tinc_conf.display()))
    })?;

    let mut config = tinc_conf::Config::new();
    config.merge(entries);

    let raw = config
        .lookup("Name")
        .next()
        .map(tinc_conf::Entry::get_str)
        .ok_or_else(|| {
            CmdError::BadInput(format!("Could not find Name in {}.", tinc_conf.display()))
        })?;

    // C: `return replace_name(value)`. The expansion + check_id.
    #[cfg(unix)]
    {
        names::replace_name(raw).map_err(CmdError::BadInput)
    }
    #[cfg(not(unix))]
    {
        // Windows doesn't have gethostname in the same shape. Punt
        // until we have a Windows builder. The literal-name path
        // (no `$` prefix) doesn't need it.
        if raw.starts_with('$') {
            Err(CmdError::BadInput(
                "$-expansion not supported on this platform yet".into(),
            ))
        } else if check_id(raw) {
            Ok(raw.to_owned())
        } else {
            Err(CmdError::BadInput("Invalid name for myself!".into()))
        }
    }
}

// Export

/// `export` (the inner helper, not `cmd_export`). Write one host file
/// to `out`, prefixed with `Name = X`, with any `Name =` lines from
/// the file itself stripped.
///
/// C: `tincctl.c:2474-2500`.
///
/// # Errors
/// I/O on the host file or `out`.
pub fn export_one(paths: &Paths, name: &str, mut out: impl Write) -> Result<(), CmdError> {
    let path = paths.host_file(name);
    // C: `fopen(filename, "r")` then `fgets` loop. We `read_to_string`.
    // Host files are small (a few KB at most — public key + a handful
    // of config lines). The streaming read isn't buying anything.
    //
    // `read_to_string` does mean we reject non-UTF-8 host files, which
    // the C wouldn't. Host files are ASCII in practice (config keys
    // are ASCII, b64 is ASCII, addresses are ASCII). A non-UTF-8 host
    // file is corruption, and failing loudly is better than passing
    // corrupted bytes to a peer.
    let content = fs::read_to_string(&path).map_err(io_err(&path))?;

    // C: `fprintf(out, "Name = %s\n", name)`.
    writeln!(out, "Name = {name}").map_err(io_err("<stdout>"))?;

    for line in content.lines() {
        // C: `if(strcspn(buf, "\t =") != 4 || strncasecmp(buf, "Name", 4))`.
        //
        // Unpack: `strcspn(buf, "\t =")` is "length of the leading run
        // containing none of TAB/SPACE/=". If that's exactly 4, AND
        // the first 4 bytes are "Name" (case-insensitive), skip.
        //
        // So `Name = foo`   → strcspn=4, prefix matches → skip
        //    `Name=foo`     → strcspn=4, prefix matches → skip
        //    `Name foo`     → strcspn=4, prefix matches → skip
        //    `Namespace =`  → strcspn=9, doesn't match  → keep
        //    `name = foo`   → strcspn=4, strncasecmp matches → skip
        //    `Named = foo`  → strcspn=5, doesn't match  → keep
        //    ` Name = foo`  → strcspn=0, doesn't match  → keep ← note!
        //
        // The leading-space case is odd: a line ` Name = foo` (with a
        // space) is *kept*. The C config parser strips leading
        // whitespace before tokenizing, so ` Name = foo` *is* a Name
        // line as far as the daemon is concerned. But export's filter
        // doesn't strip, so it doesn't catch it. This is a (harmless,
        // unlikely) C bug. We replicate it — the cost of not
        // replicating is a behavioral difference, the cost of
        // replicating is one comment.
        if is_name_line(line) {
            continue;
        }
        // C: `fputs(buf, out)`. The C `buf` includes the `fgets`
        // newline; `lines()` strips it; `writeln!` puts it back.
        // Net effect: we normalize CRLF→LF if the input had CRLF.
        // Intentional — the C's `fputs` would preserve CRLF, but tinc
        // host files written by tinc are LF, and a CRLF file came from
        // a Windows editor and the CR will confuse the next reader.
        // This is a tiny "fix" but it's the kind that doesn't break
        // anything (the config parser strips trailing whitespace
        // including CR).
        writeln!(out, "{line}").map_err(io_err("<stdout>"))?;
    }

    Ok(())
}

/// `Name =` line filter. See the call site in `export_one` for the
/// full breakdown of what this matches.
fn is_name_line(line: &str) -> bool {
    // `strcspn(buf, "\t =")` — length of the prefix containing none
    // of these bytes. We're working in bytes because the C does
    // (and TAB/SPACE/= are ASCII so byte-index == char-index for the
    // boundary).
    let stop = line
        .bytes()
        .position(|b| b == b'\t' || b == b' ' || b == b'=')
        .unwrap_or(line.len());

    // `!= 4` — must be exactly 4.
    if stop != 4 {
        return false;
    }

    // `strncasecmp(buf, "Name", 4)` — first 4 bytes, case-insensitive.
    // We checked stop==4 so the slice is in-bounds; ASCII bytes mean
    // the byte slice is also a valid str slice.
    line[..4].eq_ignore_ascii_case("Name")
}

/// `cmd_export`. Just `get_my_name` then `export_one`.
///
/// C: `tincctl.c:2503-2525`.
///
/// The C's `if(!tty) fclose(stdout)` is dropped. It exists so the
/// other end of a pipe sees EOF before this process exits (relevant
/// for `exchange` where stdout goes to a peer's stdin). Rust's
/// `stdout().lock()` is dropped at scope exit, which flushes; process
/// exit closes the fd. The peer sees EOF either way. The explicit
/// close was a C-ism for the `FILE*` buffer, not an fd concern.
///
/// # Errors
/// `get_my_name` or `export_one` failed.
pub fn export(paths: &Paths, out: impl Write) -> Result<(), CmdError> {
    let name = get_my_name(paths)?;
    export_one(paths, &name, out)
}

/// `cmd_export_all`. Walk `hosts/`, export each, separator between.
///
/// C: `tincctl.c:2527-2567`.
///
/// **Ordering**: the C uses `readdir` order, which is filesystem-
/// dependent (ext4: insertion order, sort of; tmpfs: hash order;
/// btrfs: something else). We sort. This is a behavioral difference
/// from the C, but a *good* one — the output is deterministic, which
/// makes `tinc export-all > all.txt` diffable across machines, and
/// makes tests not depend on the filesystem.
///
/// The C's "best effort, |= results, continue on error" is preserved:
/// one bad host file doesn't stop the whole export.
///
/// # Errors
/// `hosts_dir` can't be opened. Per-file errors are accumulated.
pub fn export_all(paths: &Paths, mut out: impl Write) -> Result<(), CmdError> {
    let hosts_dir = paths.hosts_dir();
    let mut entries: Vec<String> = fs::read_dir(&hosts_dir)
        .map_err(io_err(&hosts_dir))?
        .filter_map(|e| {
            // C: `if(!check_id(ent->d_name)) continue`. Silently skip
            // anything that doesn't look like a node name — `.`, `..`,
            // editor swap files, README, whatever.
            //
            // `to_str()` failing (non-UTF-8 dirent) → skip. The C's
            // `check_id` would also skip it (any byte ≥0x80 fails
            // `isalnum`), so same outcome.
            let name = e.ok()?.file_name().to_str()?.to_owned();
            check_id(&name).then_some(name)
        })
        .collect();

    // The deviation from C: deterministic order.
    entries.sort();

    let mut first = true;
    let mut any_error = false;

    for name in &entries {
        if first {
            first = false;
        } else {
            // C: `printf("\n#--...--#\n")`. Blank line, separator, newline.
            // The blank line ends up trailing the *previous* host's
            // content on the import side. See module doc.
            writeln!(out).map_err(io_err("<stdout>"))?;
            writeln!(out, "{SEPARATOR}").map_err(io_err("<stdout>"))?;
        }

        // C: `result |= export(...)`. Best-effort: log error, continue.
        if let Err(e) = export_one(paths, name, &mut out) {
            eprintln!("{e}");
            any_error = true;
        }
    }

    if any_error {
        // The C returns the OR of error codes; in practice that's
        // always 1 if any failed. We map to a generic CmdError. The
        // per-file message already went to stderr above.
        Err(CmdError::BadInput(
            "Some host files could not be exported".into(),
        ))
    } else {
        Ok(())
    }
}

// Import

/// `cmd_import`. Read the export-blob format from `inp`, write
/// `hosts/NAME` for each `Name = NAME` section.
///
/// C: `tincctl.c:2569-2648`.
///
/// `force`: if false, skip hosts whose file already exists (with a
/// stderr warning). If true, truncate-and-overwrite. C: `--force`
/// global, `if(!force && !access(filename, F_OK))`.
///
/// Returns the count of files written. C `cmd_import` returns 0 on
/// success / 1 on failure; we let the caller map count→exit-code.
/// Count is more useful for tests.
///
/// ## The state machine
///
/// ```text
///         ┌─ "Name = X" ─→ [open hosts/X, count++]
///   line ─┤  "#---...#"  ─→ [skip]
///         └─ anything else → [write to current file, or warn-once if none]
/// ```
///
/// The "current file" can be `None` in two cases: junk before the
/// first `Name =`, or a `Name =` whose file already exists (with
/// `!force`). In both cases content lines are silently dropped.
///
/// ## On the `sscanf` parse
///
/// C: `sscanf(buf, "Name = %4095s", name)`. This matches:
/// - `Name = foo`      → "foo"
/// - `Name =  foo`     → "foo" (`%s` skips leading whitespace)
/// - `Name = foo bar`  → "foo" (`%s` stops at whitespace)
/// - `Name=foo`        → 0 matches (literal " " in fmt doesn't match nothing)
/// - `name = foo`      → 0 matches (literal "Name" is case-sensitive)
/// - ` Name = foo`     → 0 matches (literal "N" doesn't match " ")
///
/// So *only* the canonical `Name = X` form. The export side always
/// writes that exact form, so import only needs to match what export
/// produces. A hand-edited blob with `Name=foo` won't import.
/// Replicated faithfully because looser matching could change behavior
/// on weird inputs (a host file containing `Name=something` as a
/// *comment* would suddenly trigger a section boundary).
///
/// # Errors
/// - I/O writing a host file (NOT skip-because-exists; that's a warning)
/// - `Name =` value fails `check_id`
///
/// # Panics
/// Unreachable — `current_path` is `Some` whenever `out` is, by
/// construction (set together, cleared together). The `.unwrap()`s
/// document this invariant.
//
pub fn import(paths: &Paths, inp: impl BufRead, force: bool) -> Result<usize, CmdError> {
    let mut out: Option<BufWriter<fs::File>> = None;
    // For error messages. C: `char filename[PATH_MAX]`, set when out is.
    let mut current_path: Option<std::path::PathBuf> = None;
    let mut count = 0usize;
    let mut firstline = true;

    // C: `while(fgets(buf, sizeof(buf), in))`. We use `lines()` which
    // strips the newline; the separator match adjusts.
    //
    // `fgets` with a 4096 buffer truncates lines longer than 4095
    // chars (the rest spills into the next iteration). We don't
    // truncate. A 5000-char line is preserved. This is a tightening:
    // the C would silently corrupt a long line, we don't. No real
    // host file has lines that long (the longest is a 64-char b64
    // PEM body line).
    for line in inp.lines() {
        let line = line.map_err(io_err("<stdin>"))?;

        // ─── "Name = X" → switch files
        // C: `if(sscanf(buf, "Name = %4095s", name) == 1)`. See the
        // doc comment above for what this matches. We replicate:
        // exact prefix `"Name = "`, then take the first whitespace-
        // delimited token of the rest.
        if let Some(tail) = line.strip_prefix("Name = ") {
            firstline = false;

            // `%s` semantics: skip leading whitespace, take until
            // whitespace. `split_whitespace().next()` does exactly
            // that. Empty (`Name = ` with nothing after) → None →
            // empty string → check_id fails.
            let name = tail.split_whitespace().next().unwrap_or("");

            if !check_id(name) {
                return Err(CmdError::BadInput("Invalid Name in input!".into()));
            }

            // C: `if(out) fclose(out)`. Drop = close + flush.
            // The drop happens via reassignment below; explicit here
            // for clarity and so flush errors surface (BufWriter::drop
            // swallows errors).
            if let Some(mut prev) = out.take() {
                prev.flush()
                    .map_err(io_err(current_path.as_ref().unwrap()))?;
            }

            let path = paths.host_file(name);

            // C: `if(!force && !access(filename, F_OK))`.
            //
            // We use `try_exists()` not `exists()` — `exists()`
            // returns false on permission-denied, which would mean we
            // try to open it and fail with a different error. C's
            // `access(F_OK)` returns -1 on EACCES too (so the C also
            // tries to open and fails). Replicating the C: `exists()`.
            // Actually no — `try_exists` returning Err means we *can't
            // tell*, and the safest thing is to not overwrite. But
            // the C overwrites in that case (because `access` returned
            // nonzero). Fidelity wins: use `exists()`.
            if !force && path.exists() {
                eprintln!(
                    "Host configuration file {} already exists, skipping.",
                    path.display()
                );
                out = None;
                current_path = None;
                continue;
            }

            // C: `fopen(filename, "w")`. Truncate-and-create.
            // Not `O_EXCL` — the `!force` check above already gated
            // existence; with `force`, truncating is the *point*.
            let f = fs::File::create(&path).map_err(io_err(&path))?;
            out = Some(BufWriter::new(f));
            current_path = Some(path);
            count += 1;
            continue;
        }

        // ─── Junk before first Name → warn once
        if firstline {
            eprintln!("Junk at the beginning of the input, ignoring.");
            firstline = false;
            // C: warn, then *fall through* — the junk line itself
            // isn't written anywhere (out is None), but we still
            // check the separator below. Doesn't matter (separator
            // before any Name is junk anyway), but fidelity.
        }

        // ─── Separator → skip
        // C: `if(!strcmp(buf, "#--...--#\n"))`. The C buf includes
        // the fgets newline. Our `line` doesn't (lines() strips).
        // So we compare against SEPARATOR sans newline.
        //
        // Note: the C's strcmp means a separator line at EOF *without*
        // a trailing newline doesn't match (strcmp against the
        // with-newline string fails) and gets written as content. Our
        // `lines()` doesn't distinguish "last line had \n" from
        // "last line didn't", so we'd skip both. Tiny difference;
        // export always writes the trailing newline so this is only
        // observable on hand-crafted input. Not worth the complexity
        // to replicate.
        if line == SEPARATOR {
            continue;
        }

        // ─── Content → write to current file
        // C: `if(out) fputs(buf, out)`. Silently dropped if out==NULL.
        if let Some(f) = out.as_mut() {
            // C `buf` has the newline; we add it back.
            writeln!(f, "{line}").map_err(io_err(current_path.as_ref().unwrap()))?;
        }
    }

    // C: `if(out) fclose(out)`. Same flush-explicitly as above.
    if let Some(mut f) = out {
        f.flush().map_err(io_err(current_path.as_ref().unwrap()))?;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::PathsInput;

    /// Set up a confbase with `tinc.conf` and `hosts/NAME`.
    fn setup(name: &str, host_content: &str) -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        fs::write(confbase.join("tinc.conf"), format!("Name = {name}\n")).unwrap();
        fs::write(confbase.join("hosts").join(name), host_content).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });
        (dir, paths)
    }

    #[test]
    fn separator_is_65_chars() {
        // Belt-and-suspenders: const assert above + this. The const
        // assert catches it at compile time; this is just so a
        // `cargo test` run shows it explicitly.
        assert_eq!(SEPARATOR.len(), 65);
        assert!(SEPARATOR.starts_with("#-"));
        assert!(SEPARATOR.ends_with("-#"));
        // Exactly 63 dashes between the #s.
        assert_eq!(SEPARATOR[1..64], "-".repeat(63));
    }

    #[test]
    fn name_line_filter() {
        // The cases from the export_one comment.
        assert!(is_name_line("Name = foo"));
        assert!(is_name_line("Name=foo"));
        assert!(is_name_line("Name foo"));
        assert!(is_name_line("name = foo")); // case-insensitive
        assert!(is_name_line("NAME\tfoo"));
        assert!(!is_name_line("Namespace = foo")); // strcspn=9
        assert!(!is_name_line("Named = foo")); // strcspn=5
        assert!(!is_name_line(" Name = foo")); // strcspn=0, the C bug
        assert!(!is_name_line("")); // strcspn=0
        assert!(!is_name_line("Nam")); // strcspn=3
    }

    #[test]
    fn export_injects_name_strips_name() {
        let (_d, paths) = setup(
            "alice",
            // Host file with a Name line (unusual but legal) — should
            // get stripped. Other lines pass through.
            "Name = stale\nAddress = 192.0.2.1\nSubnet = 10.0.0.0/24\n",
        );
        let mut out = Vec::new();
        export(&paths, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Name = alice\nAddress = 192.0.2.1\nSubnet = 10.0.0.0/24\n"
        );
    }

    #[test]
    fn export_preserves_pem() {
        let (_d, paths) = setup(
            "alice",
            "Ed25519PublicKey = abcdef\n\
             -----BEGIN ED25519 PUBLIC KEY-----\n\
             SGVsbG8gd29ybGQ=\n\
             -----END ED25519 PUBLIC KEY-----\n",
        );
        let mut out = Vec::new();
        export(&paths, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // The PEM block passes through opaque.
        assert!(s.contains("-----BEGIN"));
        assert!(s.contains("SGVsbG8gd29ybGQ="));
        assert!(s.contains("-----END"));
    }

    #[test]
    fn export_all_separator_between() {
        let (_d, paths) = setup("alice", "Subnet = 10.0.1.0/24\n");
        // Add bob.
        fs::write(paths.host_file("bob"), "Subnet = 10.0.2.0/24\n").unwrap();

        let mut out = Vec::new();
        export_all(&paths, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();

        // Sorted: alice before bob.
        let alice_pos = s.find("Name = alice").unwrap();
        let bob_pos = s.find("Name = bob").unwrap();
        let sep_pos = s.find(SEPARATOR).unwrap();
        assert!(alice_pos < sep_pos);
        assert!(sep_pos < bob_pos);
        // Separator only between, not before alice.
        assert_eq!(s.matches(SEPARATOR).count(), 1);
    }

    #[test]
    fn export_all_skips_non_id_dirents() {
        let (_d, paths) = setup("alice", "Subnet = 10.0.1.0/24\n");
        // Garbage in hosts/: editor swap, README, dotfile.
        fs::write(paths.hosts_dir().join(".alice.swp"), "junk").unwrap();
        fs::write(paths.hosts_dir().join("README"), "junk").unwrap();
        fs::write(paths.hosts_dir().join("with-dash"), "junk").unwrap();

        let mut out = Vec::new();
        export_all(&paths, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // The C check is `check_id`, period. README is `[A-Za-z]+`
        // which passes — so it's a valid node name and C exports it.
        assert!(s.contains("Name = alice"));
        assert!(s.contains("Name = README")); // ← yes, really
        assert!(!s.contains("with-dash"));
        assert!(!s.contains(".alice.swp"));
    }

    #[test]
    fn import_basic() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        let blob = "Name = alice\nSubnet = 10.0.1.0/24\nAddress = 192.0.2.1\n";
        let count = import(&paths, blob.as_bytes(), false).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            fs::read_to_string(paths.host_file("alice")).unwrap(),
            "Subnet = 10.0.1.0/24\nAddress = 192.0.2.1\n"
        );
    }

    #[test]
    fn import_multi_with_separator() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        let blob = format!(
            "Name = alice\nSubnet = 10.0.1.0/24\n\n{SEPARATOR}\nName = bob\nSubnet = 10.0.2.0/24\n"
        );
        let count = import(&paths, blob.as_bytes(), false).unwrap();
        assert_eq!(count, 2);
        // The blank line before the separator went to alice's file.
        // See module doc — this is the documented quirk.
        assert_eq!(
            fs::read_to_string(paths.host_file("alice")).unwrap(),
            "Subnet = 10.0.1.0/24\n\n"
        );
        assert_eq!(
            fs::read_to_string(paths.host_file("bob")).unwrap(),
            "Subnet = 10.0.2.0/24\n"
        );
    }

    #[test]
    fn import_skip_existing_unless_force() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        // Pre-existing alice.
        fs::write(paths.host_file("alice"), "OLD CONTENT\n").unwrap();

        let blob = "Name = alice\nNEW CONTENT\n";

        // Without force: skip.
        let count = import(&paths, blob.as_bytes(), false).unwrap();
        assert_eq!(count, 0);
        assert_eq!(
            fs::read_to_string(paths.host_file("alice")).unwrap(),
            "OLD CONTENT\n"
        );

        // With force: overwrite.
        let count = import(&paths, blob.as_bytes(), true).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            fs::read_to_string(paths.host_file("alice")).unwrap(),
            "NEW CONTENT\n"
        );
    }

    #[test]
    fn import_bad_name_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        let blob = "Name = ../escape\nSubnet = 10.0.0.0/8\n";
        let err = import(&paths, blob.as_bytes(), false).unwrap_err();
        assert!(matches!(err, CmdError::BadInput(_)));
        // The dangerous file was NOT created.
        assert!(!paths.hosts_dir().join("..").join("escape").exists());
    }

    #[test]
    fn import_junk_before_name_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        // Junk before first Name = warned and dropped.
        let blob = "this is not a name line\nName = alice\nSubnet = 10.0.1.0/24\n";
        let count = import(&paths, blob.as_bytes(), false).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            fs::read_to_string(paths.host_file("alice")).unwrap(),
            "Subnet = 10.0.1.0/24\n"
        );
    }

    #[test]
    fn import_no_name_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        // No Name = line anywhere → count 0, no error (the binary
        // maps count==0 to exit 1, but the function succeeds).
        let blob = "just some\nrandom text\n";
        let count = import(&paths, blob.as_bytes(), false).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn import_name_format_is_exact() {
        // `sscanf("Name = %s")` is picky. See the doc comment.
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        // `Name=alice` (no spaces) → not a section header.
        let count = import(&paths, b"Name=alice\nfoo\n".as_slice(), false).unwrap();
        assert_eq!(count, 0);

        // `name = alice` (lowercase) → not a section header.
        let count = import(&paths, b"name = alice\nfoo\n".as_slice(), false).unwrap();
        assert_eq!(count, 0);

        // ` Name = alice` (leading space) → not a section header.
        let count = import(&paths, b" Name = alice\nfoo\n".as_slice(), false).unwrap();
        assert_eq!(count, 0);

        // `Name = alice ignored` (trailing junk) → IS a header, name=alice.
        // %s stops at whitespace.
        let count = import(&paths, b"Name = alice ignored\nfoo\n".as_slice(), false).unwrap();
        assert_eq!(count, 1);
        assert!(paths.host_file("alice").exists());
    }

    /// **Round-trip**: export → import recreates the file. This is
    /// the actual contract — the format is whatever export produces,
    /// import is its inverse.
    #[test]
    fn roundtrip() {
        let original = "Address = 192.0.2.1\n\
                        Port = 655\n\
                        Subnet = 10.0.1.0/24\n\
                        Subnet = fd00::/64\n\
                        Ed25519PublicKey = Pg2fEkaQ9lLAnEDV+ZOfu8I0il9rmrQaY+WYDOzeavK\n";

        // ─── Export side
        let (_export_dir, export_paths) = setup("alice", original);
        let mut blob = Vec::new();
        export(&export_paths, &mut blob).unwrap();

        // ─── Import side (different confbase)
        let import_dir = tempfile::tempdir().unwrap();
        let import_base = import_dir.path().join("peer");
        fs::create_dir_all(import_base.join("hosts")).unwrap();
        let import_paths = Paths::for_cli(&PathsInput {
            confbase: Some(import_base),
            ..Default::default()
        });

        let count = import(&import_paths, blob.as_slice(), false).unwrap();
        assert_eq!(count, 1);

        // ─── The proof
        let imported = fs::read_to_string(import_paths.host_file("alice")).unwrap();
        assert_eq!(imported, original);
    }

    /// Round-trip through export-all + separator. Tests that the
    /// separator is correctly injected by export_all and stripped by
    /// import.
    #[test]
    fn roundtrip_multi() {
        let alice_content = "Subnet = 10.0.1.0/24\nAddress = 192.0.2.1\n";
        let bob_content = "Subnet = 10.0.2.0/24\nAddress = 192.0.2.2\n";

        let (_d, export_paths) = setup("alice", alice_content);
        fs::write(export_paths.host_file("bob"), bob_content).unwrap();

        let mut blob = Vec::new();
        export_all(&export_paths, &mut blob).unwrap();

        let import_dir = tempfile::tempdir().unwrap();
        let import_base = import_dir.path().join("peer");
        fs::create_dir_all(import_base.join("hosts")).unwrap();
        let import_paths = Paths::for_cli(&PathsInput {
            confbase: Some(import_base),
            ..Default::default()
        });

        let count = import(&import_paths, blob.as_slice(), false).unwrap();
        assert_eq!(count, 2);

        // alice gets the trailing blank line from the export-side
        // `\n#---..#\n` — the `\n` before the separator is content.
        // bob doesn't (no separator after the last host).
        // This is the documented quirk.
        assert_eq!(
            fs::read_to_string(import_paths.host_file("alice")).unwrap(),
            format!("{alice_content}\n")
        );
        assert_eq!(
            fs::read_to_string(import_paths.host_file("bob")).unwrap(),
            bob_content
        );
    }

    #[test]
    fn get_my_name_reads_config() {
        let (_d, paths) = setup("alice", "");
        assert_eq!(get_my_name(&paths).unwrap(), "alice");
    }

    #[test]
    fn get_my_name_missing_tinc_conf() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(dir.path().to_path_buf()),
            ..Default::default()
        });
        // No tinc.conf → error mentioning the path.
        let err = get_my_name(&paths).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("tinc.conf"));
    }

    #[test]
    fn get_my_name_no_name_key() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        fs::create_dir_all(&confbase).unwrap();
        // tinc.conf exists but has no Name line.
        fs::write(confbase.join("tinc.conf"), "Port = 655\n").unwrap();
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });
        let err = get_my_name(&paths).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Could not find Name"));
    }
}
