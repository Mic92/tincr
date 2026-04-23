//! `tinc export`/`import`/`export-all`/`exchange`/`exchange-all`.
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
//!   Known wart (C parity, `tincctl.c`): a host-file line byte-equal
//!   to the separator is dropped on import. Harmless — it's a `#`
//!   comment — and fixing it would break blob interop with C `tinc
//!   export`.
//!
//! - **PEM blocks pass through opaque.** Export doesn't know or care
//!   about `-----BEGIN`. The host file is bytes; export ships bytes.
//!   `tinc-conf::parse_reader`'s PEM-stripping is a different
//!   concern (it's for *config lookup*, where you want
//!   `Ed25519PublicKey =` and not the armor body as a key=value).
//!
//! - **The blank line before the separator** (`\n#---..#\n`) is
//!   consumed by import as part of the previous host's content.
//!   Harmless but a "fix" would break round-trip.

use std::fs;
use std::io::{BufRead, BufWriter, Write};

use crate::cmd::{CmdError, io_err};
use crate::names::{self, Paths, check_id};

// `import` matches against the 65-char `#---...---#` separator
// exactly; we keep the newline separate so `export_all` can write
// `\n` + SEPARATOR + `\n` (it wants a blank line *before*). The
// invitation file format reuses the same string, so the constant
// lives in `cmd::invite`.
use super::invite::SEPARATOR;

/// `get_my_name` — read `Name = X` from `tinc.conf`, expand `$HOST`.
///
/// Uses `tinc-conf` for tokenization. Reads the whole file, looks
/// up `Name`, returns the first hit. `tinc.conf` is ~5 lines.
///
/// Returns the *post-expansion* name. `Name = $HOST` resolves.
///
/// # Errors
/// - `tinc.conf` doesn't exist or can't be read
/// - No `Name =` line
/// - `replace_name` fails (bad env var, gethostname failed, fails `check_id`)
pub fn get_my_name(paths: &Paths) -> Result<String, CmdError> {
    let tinc_conf = paths.tinc_conf();

    let config = tinc_conf::Config::read(&tinc_conf)
        .map_err(|e| CmdError::BadInput(format!("Could not open {}: {e}", tinc_conf.display())))?;

    let raw = config
        .lookup("Name")
        .next()
        .map(tinc_conf::Entry::get_str)
        .ok_or_else(|| {
            CmdError::BadInput(format!("Could not find Name in {}.", tinc_conf.display()))
        })?;

    names::replace_name(raw).map_err(CmdError::BadInput)
}

// Export

/// `export` (the inner helper, not `cmd_export`). Write one host file
/// to `out`, prefixed with `Name = X`, with any `Name =` lines from
/// the file itself stripped.
///
/// # Errors
/// I/O on the host file or `out`.
pub fn export_one(paths: &Paths, name: &str, mut out: impl Write) -> Result<(), CmdError> {
    let path = paths.host_file(name);
    // Host files are small (a few KB at most). `read_to_string`
    // rejects non-UTF-8; host files are ASCII in practice (config
    // keys, b64, addresses). A non-UTF-8 host file is corruption.
    let content = fs::read_to_string(&path).map_err(io_err(&path))?;

    writeln!(out, "Name = {name}").map_err(io_err("<stdout>"))?;

    for line in content.lines() {
        // Skip any line whose `split_kv` key is `Name` (case-
        // insensitive): `Name = foo`, `Name=foo`, `name\tfoo`, but
        // not `Namespace = ` nor ` Name = foo` (leading space — a
        // harmless upstream quirk we keep for fidelity; the config
        // parser would lstrip, this filter doesn't).
        if is_name_line(line) {
            continue;
        }
        // `lines()` strips the newline; `writeln!` puts LF back.
        // Net effect: we normalize CRLF→LF. Intentional — a CRLF
        // file came from a Windows editor and the CR confuses the
        // next reader. The config parser strips trailing whitespace
        // including CR, so this doesn't break anything.
        writeln!(out, "{line}").map_err(io_err("<stdout>"))?;
    }

    Ok(())
}

/// `Name =` line filter. See the call site in `export_one` for the
/// full breakdown of what this matches.
fn is_name_line(line: &str) -> bool {
    // `split_kv` is the canonical `strcspn(line, "\t =")` tokenizer.
    // Same key-span semantics as the open-coded byte scan it replaced.
    tinc_conf::split_kv(line).0.eq_ignore_ascii_case("Name")
}

/// `cmd_export`. Just `get_my_name` then `export_one`.
///
/// Upstream's `if(!tty) fclose(stdout)` is dropped: Rust's
/// `stdout().lock()` flushes on drop and process exit closes the
/// fd. The peer sees EOF either way.
///
/// # Errors
/// `get_my_name` or `export_one` failed.
pub fn export(paths: &Paths, out: impl Write) -> Result<(), CmdError> {
    let name = get_my_name(paths)?;
    export_one(paths, &name, out)
}

/// `cmd_export_all`. Walk `hosts/`, export each, separator between.
///
/// **Ordering**: we sort. Upstream uses `readdir` order (filesystem-
/// dependent). Sorting makes `tinc export-all > all.txt` diffable
/// across machines and tests deterministic.
///
/// Best effort: one bad host file doesn't stop the whole export.
///
/// # Errors
/// `hosts_dir` can't be opened. Per-file errors are accumulated.
pub fn export_all(paths: &Paths, mut out: impl Write) -> Result<(), CmdError> {
    let hosts_dir = paths.hosts_dir();
    let mut entries: Vec<String> = fs::read_dir(&hosts_dir)
        .map_err(io_err(&hosts_dir))?
        .filter_map(|e| {
            // Silently skip anything that doesn't look like a node
            // name — `.`, `..`, editor swap files, README, whatever.
            // `to_str()` failing (non-UTF-8 dirent) → also skip;
            // `check_id` would reject it anyway (bytes ≥0x80).
            let name = e.ok()?.file_name().to_str()?.to_owned();
            check_id(&name).then_some(name)
        })
        .collect();

    entries.sort();

    let mut first = true;
    let mut any_error = false;

    for name in &entries {
        if first {
            first = false;
        } else {
            // Blank line, separator, newline. The blank line ends up
            // trailing the *previous* host's content on the import
            // side. See module doc.
            writeln!(out).map_err(io_err("<stdout>"))?;
            writeln!(out, "{SEPARATOR}").map_err(io_err("<stdout>"))?;
        }

        // Best-effort: log error, continue.
        if let Err(e) = export_one(paths, name, &mut out) {
            eprintln!("{e}");
            any_error = true;
        }
    }

    if any_error {
        // The per-file message already went to stderr above.
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
/// `force`: if false, skip hosts whose file already exists (with a
/// stderr warning). If true, truncate-and-overwrite.
///
/// Returns the count of files written; the caller maps count→exit.
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
/// ## Section header parse
///
/// Matches *only* the canonical `Name = X` form:
/// - `Name = foo`      → "foo"
/// - `Name =  foo`     → "foo" (skips leading whitespace)
/// - `Name = foo bar`  → "foo" (stops at whitespace)
/// - `Name=foo`        → no match (literal " " required)
/// - `name = foo`      → no match (case-sensitive)
/// - ` Name = foo`     → no match (no leading whitespace)
///
/// The export side always writes that exact form, so import only
/// needs to match what export produces. A hand-edited blob with
/// `Name=foo` won't import. Looser matching could change behavior
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
    // For error messages. Set when `out` is.
    let mut current_path: Option<std::path::PathBuf> = None;
    let mut count = 0usize;
    let mut firstline = true;

    // `lines()` strips the newline; the separator match adjusts.
    // We don't truncate long lines (upstream's 4096 buffer would).
    // No real host file has lines that long anyway.
    for line in inp.lines() {
        let line = line.map_err(io_err("<stdin>"))?;

        // ─── "Name = X" → switch files
        // Exact prefix `"Name = "`, then take the first whitespace-
        // delimited token. See doc comment for what this matches.
        if let Some(tail) = line.strip_prefix("Name = ") {
            firstline = false;

            // Skip leading whitespace, take until whitespace.
            // Empty (`Name = ` with nothing after) → None →
            // empty string → check_id fails.
            let name = tail.split_whitespace().next().unwrap_or("");

            if !check_id(name) {
                return Err(CmdError::BadInput("Invalid Name in input!".into()));
            }

            // Explicit flush so errors surface (BufWriter::drop
            // swallows errors).
            if let Some(mut prev) = out.take() {
                prev.flush()
                    .map_err(io_err(current_path.as_ref().unwrap()))?;
            }

            let path = paths.host_file(name);

            // `!force` → O_EXCL (create_new); `force` → truncate.
            let mut opts = fs::OpenOptions::new();
            opts.write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
            }
            if force {
                opts.create(true).truncate(true);
            } else {
                opts.create_new(true);
            }
            let f = match opts.open(&path) {
                Ok(f) => f,
                Err(e) if !force && e.kind() == std::io::ErrorKind::AlreadyExists => {
                    eprintln!(
                        "Host configuration file {} already exists, skipping.",
                        path.display()
                    );
                    out = None;
                    current_path = None;
                    continue;
                }
                Err(e) => return Err(io_err(&path)(e)),
            };
            out = Some(BufWriter::new(f));
            current_path = Some(path);
            count += 1;
            continue;
        }

        // ─── Junk before first Name → warn once
        if firstline {
            eprintln!("Junk at the beginning of the input, ignoring.");
            firstline = false;
        }

        // ─── Separator → skip
        // `lines()` strips the newline, so compare sans newline.
        // Tiny upstream difference: a separator at EOF without a
        // trailing newline would be content there but skipped here.
        // Export always writes the trailing newline; not worth
        // replicating for hand-crafted input.
        if line == SEPARATOR {
            continue;
        }

        // ─── Content → write to current file (silently dropped if none)
        if let Some(f) = out.as_mut() {
            writeln!(f, "{line}").map_err(io_err(current_path.as_ref().unwrap()))?;
        }
    }

    if let Some(mut f) = out {
        f.flush().map_err(io_err(current_path.as_ref().unwrap()))?;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ConfDir;

    /// `ConfDir::with_name` + overwrite `hosts/NAME` with `host_content`.
    fn setup(name: &str, host_content: &str) -> ConfDir {
        ConfDir::with_name(name).with_host(name, host_content)
    }

    /// Empty confbase with `hosts/` only. Import-side fixture.
    fn bare() -> ConfDir {
        ConfDir::bare()
    }

    #[test]
    fn name_line_filter() {
        // The cases from the export_one comment.
        assert!(is_name_line("Name = foo"));
        assert!(is_name_line("Name=foo"));
        assert!(is_name_line("Name foo"));
        assert!(is_name_line("name = foo")); // case-insensitive
        assert!(is_name_line("NAME\tfoo"));
        assert!(!is_name_line("Namespace = foo")); // stop=9
        assert!(!is_name_line("Named = foo")); // stop=5
        assert!(!is_name_line(" Name = foo")); // stop=0, the upstream bug
        assert!(!is_name_line("")); // stop=0
        assert!(!is_name_line("Nam")); // stop=3
    }

    #[test]
    fn export_injects_name_strips_name() {
        let cd = setup(
            "alice",
            // Host file with a Name line (unusual but legal) — should
            // get stripped. Other lines pass through.
            "Name = stale\nAddress = 192.0.2.1\nSubnet = 10.0.0.0/24\n",
        );
        let mut out = Vec::new();
        export(cd.paths(), &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Name = alice\nAddress = 192.0.2.1\nSubnet = 10.0.0.0/24\n"
        );
    }

    #[test]
    fn export_preserves_pem() {
        let cd = setup(
            "alice",
            "Ed25519PublicKey = abcdef\n\
             -----BEGIN ED25519 PUBLIC KEY-----\n\
             SGVsbG8gd29ybGQ=\n\
             -----END ED25519 PUBLIC KEY-----\n",
        );
        let mut out = Vec::new();
        export(cd.paths(), &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // The PEM block passes through opaque.
        assert!(s.contains("-----BEGIN"));
        assert!(s.contains("SGVsbG8gd29ybGQ="));
        assert!(s.contains("-----END"));
    }

    #[test]
    fn export_all_separator_between() {
        let cd = setup("alice", "Subnet = 10.0.1.0/24\n");
        let paths = cd.paths().clone();
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
        let cd = setup("alice", "Subnet = 10.0.1.0/24\n");
        let paths = cd.paths().clone();
        // Garbage in hosts/: editor swap, README, dotfile.
        fs::write(paths.hosts_dir().join(".alice.swp"), "junk").unwrap();
        fs::write(paths.hosts_dir().join("README"), "junk").unwrap();
        fs::write(paths.hosts_dir().join("with-dash"), "junk").unwrap();

        let mut out = Vec::new();
        export_all(&paths, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // The check is `check_id`, period. README is `[A-Za-z]+`
        // which passes — so it's a valid node name and gets exported.
        assert!(s.contains("Name = alice"));
        assert!(s.contains("Name = README")); // ← yes, really
        assert!(!s.contains("with-dash"));
        assert!(!s.contains(".alice.swp"));
    }

    #[test]
    fn import_basic() {
        let cd = bare();
        let paths = cd.paths().clone();

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
        let cd = bare();
        let paths = cd.paths().clone();

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
        let cd = bare();
        let paths = cd.paths().clone();

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
        let cd = bare();
        let paths = cd.paths().clone();

        let blob = "Name = ../escape\nSubnet = 10.0.0.0/8\n";
        let err = import(&paths, blob.as_bytes(), false).unwrap_err();
        assert!(matches!(err, CmdError::BadInput(_)));
        // The dangerous file was NOT created.
        assert!(!paths.hosts_dir().join("..").join("escape").exists());
    }

    #[test]
    fn import_junk_before_name_is_ignored() {
        let cd = bare();
        let paths = cd.paths().clone();

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
        let cd = bare();
        let paths = cd.paths().clone();

        // No Name = line anywhere → count 0, no error (the binary
        // maps count==0 to exit 1, but the function succeeds).
        let blob = "just some\nrandom text\n";
        let count = import(&paths, blob.as_bytes(), false).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn import_name_format_is_exact() {
        // The header parse is picky. See the doc comment.
        let cd = bare();
        let paths = cd.paths().clone();

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
        let export_cd = setup("alice", original);
        let export_paths = export_cd.paths().clone();
        let mut blob = Vec::new();
        export(&export_paths, &mut blob).unwrap();

        // ─── Import side (different confbase)
        let import_cd = bare();
        let import_paths = import_cd.paths().clone();

        let count = import(&import_paths, blob.as_slice(), false).unwrap();
        assert_eq!(count, 1);

        // ─── The proof
        let imported = fs::read_to_string(import_paths.host_file("alice")).unwrap();
        assert_eq!(imported, original);
    }

    /// Round-trip through export-all + separator. Tests that the
    /// separator is correctly injected by `export_all` and stripped by
    /// import.
    #[test]
    fn roundtrip_multi() {
        let alice_content = "Subnet = 10.0.1.0/24\nAddress = 192.0.2.1\n";
        let bob_content = "Subnet = 10.0.2.0/24\nAddress = 192.0.2.2\n";

        let export_cd = setup("alice", alice_content);
        let export_paths = export_cd.paths().clone();
        fs::write(export_paths.host_file("bob"), bob_content).unwrap();

        let mut blob = Vec::new();
        export_all(&export_paths, &mut blob).unwrap();

        let import_cd = bare();
        let import_paths = import_cd.paths().clone();

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
        let cd = setup("alice", "");
        let paths = cd.paths().clone();
        assert_eq!(get_my_name(&paths).unwrap(), "alice");
    }

    #[test]
    fn get_my_name_missing_tinc_conf() {
        let cd = ConfDir::bare();
        // No tinc.conf → error mentioning the path.
        let err = get_my_name(cd.paths()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("tinc.conf"));
    }

    #[test]
    fn get_my_name_no_name_key() {
        let cd = bare();
        let paths = cd.paths().clone();
        // tinc.conf exists but has no Name line.
        fs::write(paths.tinc_conf(), "Port = 655\n").unwrap();
        let err = get_my_name(&paths).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Could not find Name"));
    }
}
