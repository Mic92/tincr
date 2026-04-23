//! `parse_config_line`, `read_config_file`, the config tree.

use std::cmp::Ordering;
use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

// ────────────────────────────────────────────────────────────────────
// Line parser

/// Error from a single line. Carries enough context for a useful
/// diagnostic: variable name, file, line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The key half (everything before the separator). Present even on
    /// error — C logs the variable name in the diagnostic.
    pub variable: String,
    /// Human-readable problem. `"no value"` is currently the only one
    /// `parse_config_line` produces; the typed getters add more.
    pub reason: &'static str,
    /// Where it came from.
    pub source: Source,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} for variable `{}' {}",
            self.reason, self.variable, self.source
        )
    }
}

impl std::error::Error for ParseError {}

/// Provenance: where an entry came from. Determines lookup priority
/// (cmdline beats file) and diagnostic phrasing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `tincd -o Key=Value`. The C represents this as `file == NULL`.
    /// `line` is the argv index, used for stable sort within cmdline
    /// options (last `-o` for a given key wins via `lookup_config_next`
    /// — actually no: *first* wins, because lookup returns the first
    /// in sort order, which is the lowest line). Doesn't really matter
    /// for single-valued keys; matters for `Subnet` accumulation.
    Cmdline { line: u32 },
    /// `tinc.conf`, `hosts/foo`, `conf.d/*.conf`.
    File { path: PathBuf, line: u32 },
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cmdline { line } => write!(f, "in command line option {line}"),
            Self::File { path, line } => {
                write!(
                    f,
                    "on line {line} while reading config file {}",
                    path.display()
                )
            }
        }
    }
}

/// `parse_config_line`. Splits one line into `(variable, value)`.
///
/// The separator grammar, in PCRE:
///
/// ```text
/// ^(\S+)[\t ]*=?[\t ]*(.*?)[\t ]*$
/// ```
///
/// — except the C *doesn't* require `\S+` for the variable (it uses
/// `strcspn(value, "\t =")` which stops at the first `\t`, space, or
/// `=`, so the variable is everything-before-first-separator-char).
/// And the trailing strip is `[\t ]` only, not full Unicode whitespace.
///
/// Differences from the C:
///
///  - **All-whitespace lines.** C does `while(strchr("\t ", *--eol))`
///    which reads `line[-1]` if the input is all `\t `/space (eol
///    starts at the NUL, decrements past start). It happens to work
///    because the read-back-into-the-stack-frame doesn't crash. We
///    just stop at start-of-string. Such lines are filtered out by
///    the caller anyway (`!*line` after the strip, `read_config_file`
///    line 296).
///
///  - **No 1024-byte buffer truncation.** We accept arbitrary length — if someone has a 2KB `Subnet` value something
///    has gone wrong upstream of the parser.
///
/// Returns `None` for lines that should be skipped (empty after
/// trailing-strip), `Some(Err)` for "has a key but no value",
/// `Some(Ok)` otherwise. The caller is expected to have already
/// filtered `#` comments and PEM armor — those *would* parse here
/// (e.g. `# foo` → variable=`#`, value=`foo`), the filtering is one
/// layer up.
#[must_use]
pub fn parse_line(line: &str, source: Source) -> Option<Result<Entry, ParseError>> {
    // Trailing strip: `\t` and ` ` only. The empty-line check is on the
    // *original* (pre-trailing-strip) line, so a line of pure spaces
    // actually *enters* `parse_config_line` and hits the `*--eol`
    // underflow. We instead make this fn idempotent about it:
    // empty-after-strip → skip.
    let line = line.trim_end_matches(['\t', ' ']);
    if line.is_empty() {
        return None;
    }

    let (variable, value) = split_kv(line);
    let variable = variable.to_owned();

    // Empty value is an error. Variable can be empty (line starting
    // with `=` or space) and that's *not* checked — it'll fail
    // downstream at `lookup_config` time (no key matches
    // ""). We don't add a check the C doesn't have.
    if value.is_empty() {
        return Some(Err(ParseError {
            variable,
            reason: "no value",
            source,
        }));
    }

    Some(Ok(Entry {
        key_folded: ascii_fold(&variable),
        variable,
        value: value.to_owned(),
        source,
    }))
}

/// The `strcspn(line, "\t =")` tokenizer used everywhere tinc reads a
/// `key [= ]value` pair: split at first of tab/space/`=`, then skip
/// `[\t ]*`, an optional `=`, then `[\t ]*` again.
///
/// `Port = 655` → ("Port", "655"). `Port=655` → ("Port", "655").
/// `Port` → ("Port", ""). `=655` → ("", "655"). No trimming of either
/// end — callers strip trailing newlines/whitespace and check for
/// empty key/value as their context demands.
///
/// Safe to slice at the cut points because every separator is ASCII
/// and ASCII bytes never appear inside multi-byte UTF-8 sequences.
#[must_use]
pub fn split_kv(line: &str) -> (&str, &str) {
    let key_end = line.find(['\t', ' ', '=']).unwrap_or(line.len());
    let rest = &line[key_end..];
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let val = rest.trim_start_matches([' ', '\t']);
    (&line[..key_end], val)
}

/// Case-fold for lookup. C uses `strcasecmp` which is locale-dependent
/// in theory but ASCII-only in practice on every target tinc runs on.
/// We pin it to ASCII explicitly. Non-ASCII bytes pass through — they
/// never appear in valid variable names but `strcasecmp` doesn't
/// reject them either, just compares them literally.
fn ascii_fold(s: &str) -> String {
    s.bytes().map(|b| b.to_ascii_lowercase() as char).collect()
}

// ────────────────────────────────────────────────────────────────────
// File reader

/// `read_config_file`. Line loop with comment/blank/PEM-block skip.
///
/// The PEM skip (`-----BEGIN`..`-----END`) is what makes a `hosts/foo`
/// file with key armor at the bottom Just Work — the parser steps over
/// the base64 body without trying to interpret `IBazFoo+/...` as
/// `key=value`.
///
/// C reads with `fgets` into a fixed 1024-byte buffer; we read raw
/// bytes and lossily decode (so a stray Latin-1 byte in a comment, as
/// `fgets` would tolerate, doesn't hard-fail the whole file), strip a
/// leading UTF-8 BOM, and accept `\r\n`.
///
/// First parse error aborts (matches C: `if(!cfg) break;`). I/O errors
/// also abort. The C distinguishes "EOF cleanly" from "fgets failed" via
/// `feof(fp)`; we get the same from `lines()` ending vs erroring.
///
/// # Errors
/// Returns the first I/O error or parse error encountered. Partial
/// results are discarded — the C does `break` on parse error and
/// returns `false`, leaving the tree half-populated; we're stricter
/// here (caller gets nothing). If half-populated turns out to be
/// load-bearing (it shouldn't — `read_server_config` propagates the
/// `false` and the daemon exits), we'll revisit.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Vec<Entry>, ReadError> {
    let path = path.as_ref();
    let f = std::fs::File::open(path).map_err(|e| ReadError::Io {
        path: path.to_owned(),
        err: e,
    })?;
    parse_reader(f, path)
}

/// Hard cap on a single config line. Comfortably fits PEM armor and long Subnet lists.
pub const MAX_LINE_LEN: usize = 4096;
/// Hard cap on parsed entries per file.
pub const MAX_ENTRIES: usize = 4096;

/// Same as [`parse_file`] but over an arbitrary `Read`. The `path` is
/// for diagnostics only (stamped into each [`Entry::source`]).
///
/// # Errors
/// See [`parse_file`].
pub fn parse_reader(r: impl Read, path: &Path) -> Result<Vec<Entry>, ReadError> {
    let mut entries = Vec::new();
    let mut in_pem = false;
    let mut br = BufReader::new(r);
    let mut buf = Vec::new();
    let mut lineno = 0u32;

    loop {
        buf.clear();
        let n = br.read_until(b'\n', &mut buf).map_err(|e| ReadError::Io {
            path: path.to_owned(),
            err: e,
        })?;
        if n == 0 {
            break;
        }
        lineno = lineno.saturating_add(1);
        // Strip UTF-8 BOM (Notepad) so it doesn't glue onto the first key.
        let bytes = if lineno == 1 {
            buf.strip_prefix(b"\xef\xbb\xbf".as_slice()).unwrap_or(&buf)
        } else {
            &buf
        };
        // Lossy: C `fgets` is byte-oriented; don't hard-fail on Latin-1.
        let line = String::from_utf8_lossy(bytes);
        let line = line.trim_end_matches(['\n', '\r']);
        if line.len() > MAX_LINE_LEN {
            return Err(ReadError::LineTooLong {
                path: path.to_owned(),
                line: lineno,
                max: MAX_LINE_LEN,
            });
        }

        // C order matters here: blank/comment check is *before* the
        // PEM state machine, so a `#` or blank inside a PEM block would
        // be skipped without affecting `ignore`. Doesn't happen in
        // practice (PEM bodies are solid base64) but preserve the order.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_pem {
            if line.starts_with("-----END") {
                in_pem = false;
            }
            continue;
        }
        if line.starts_with("-----BEGIN") {
            in_pem = true;
            continue;
        }

        match parse_line(
            line,
            Source::File {
                path: path.to_owned(),
                line: lineno,
            },
        ) {
            None => {} // all-whitespace; skip
            Some(Err(e)) => return Err(ReadError::Parse(e)),
            Some(Ok(e)) => {
                if entries.len() >= MAX_ENTRIES {
                    return Err(ReadError::TooManyEntries {
                        path: path.to_owned(),
                        max: MAX_ENTRIES,
                    });
                }
                entries.push(e);
            }
        }
    }

    Ok(entries)
}

/// File-level read error.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// `fopen` or `fgets` failure.
    #[error("cannot open config file {}: {err}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        err: std::io::Error,
    },
    /// `parse_config_line` returned NULL.
    #[error("{0}")]
    Parse(#[source] ParseError),
    /// Line exceeded [`MAX_LINE_LEN`].
    #[error("line {line} exceeds {max} bytes in config file {}", path.display())]
    LineTooLong {
        path: PathBuf,
        line: u32,
        max: usize,
    },
    /// Entry count exceeded [`MAX_ENTRIES`].
    #[error("config file {} has more than {max} entries", path.display())]
    TooManyEntries { path: PathBuf, max: usize },
}

// ────────────────────────────────────────────────────────────────────
// The config tree

/// One `key = value` entry, with provenance.
///
/// Immutable once created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `cfg->variable`. Preserved as-written (case and all) for
    /// diagnostics — the C logs `"expected for variable %s"` with the
    /// original casing.
    pub variable: String,
    /// `cfg->value`. The string after the separator, trailing
    /// whitespace stripped, no other processing. Typed getters parse it.
    pub value: String,
    /// `(cfg->file, cfg->line)`. Determines sort order and diagnostics.
    pub source: Source,
    /// Lowercase `variable`, cached for lookup. Not in the C struct —
    /// the splay tree's `strcasecmp` does it inline. We precompute to
    /// keep [`Config::lookup`] allocation-free.
    key_folded: String,
}

impl Entry {
    /// `get_config_bool`. C accepts `"yes"`/`"no"` case-insensitively
    /// (`strcasecmp`), nothing else. Not `"true"`, not `"1"`.
    ///
    /// # Errors
    /// `Err` for any other string. Carries the entry's source for
    /// the same diagnostic the C produces.
    pub fn get_bool(&self) -> Result<bool, ParseError> {
        if self.value.eq_ignore_ascii_case("yes") {
            Ok(true)
        } else if self.value.eq_ignore_ascii_case("no") {
            Ok(false)
        } else {
            Err(self.typed_err("\"yes\" or \"no\" expected"))
        }
    }

    /// `get_config_int`. C uses `sscanf(value, "%d", ...)` — leading
    /// whitespace OK, optional sign, decimal only, *trailing garbage
    /// silently ignored* (`sscanf` returns 1 if it matched the `%d`
    /// regardless of what follows). We tighten: trailing garbage is an
    /// error. If `Port = 655x` is in someone's config, that's a typo,
    /// not a valid 655.
    ///
    /// # Errors
    /// Non-integer or out-of-`i32`-range value.
    pub fn get_int(&self) -> Result<i32, ParseError> {
        // `%d` semantics: optional leading whitespace, optional sign.
        // `i32::from_str` handles sign but not leading whitespace. The
        // value already had trailing `[\t ]` stripped at parse time;
        // strip leading too for full `%d` compat.
        self.value
            .trim_start_matches([' ', '\t'])
            .parse()
            .map_err(|_| self.typed_err("integer expected"))
    }

    /// `get_config_string`. Always succeeds for a present entry — the
    /// C just `xstrdup`s. Exists for API symmetry.
    #[must_use]
    pub fn get_str(&self) -> &str {
        &self.value
    }

    fn typed_err(&self, reason: &'static str) -> ParseError {
        ParseError {
            variable: self.variable.clone(),
            reason,
            source: self.source.clone(),
        }
    }
}

/// The config tree. C: a splay tree of `config_t*` keyed by
/// `config_compare`. We: a sorted `Vec`.
///
/// The compare function is a 4-tuple:
///
///   1. `strcasecmp(variable)` — same-key entries are contiguous
///   2. `!b->file - !a->file` — cmdline (file=NULL) before file
///   3. `a->line - b->line` — earlier line first
///   4. `strcmp(a->file, b->file)` — file name tiebreak (only matters
///      for `conf.d/` where multiple files hit the same line number)
///
/// `lookup_config` does `splay_search_closest_greater` with a probe
/// `{variable=X, file=NULL, line=0}`, which sorts at the very start
/// of X's run. So lookup returns the *first* entry for X — cmdline if
/// present (cmdline sorts first), else the lowest-line file entry.
///
/// We sort once on construction, then iterate.
#[derive(Debug, Default)]
pub struct Config {
    /// Sorted by `compare_entries`.
    entries: Vec<Entry>,
}

impl Config {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `parse_file` + `merge` into a fresh `Config`. The common case for
    /// callers that only need one file.
    ///
    /// # Errors
    /// See [`parse_file`].
    pub fn read(path: impl AsRef<Path>) -> Result<Self, ReadError> {
        let mut cfg = Self::new();
        cfg.merge(parse_file(path)?);
        Ok(cfg)
    }

    /// Absorb a batch of entries (one parsed file, or a set of cmdline
    /// `-o` options) and re-sort. The C inserts one-at-a-time into the
    /// splay tree; we batch because it doesn't matter — the only reads
    /// are after all inserts.
    pub fn merge(&mut self, entries: impl IntoIterator<Item = Entry>) {
        self.entries.extend(entries);
        // Stable sort isn't strictly needed (the compare is total) but
        // costs nothing and makes debugging easier.
        self.entries.sort_by(compare_entries);
    }

    /// `lookup_config` + `lookup_config_next`: all entries for `key`,
    /// in priority order.
    ///
    /// The dominant call pattern is single-valued keys
    /// (`.lookup("Port").next()`), but multi-valued keys (`Subnet`,
    /// `ConnectTo`, `Address`, `BroadcastSubnet`) iterate the whole
    /// run.
    ///
    /// Linear scan. Config files are tens of entries; `O(n)` here is
    /// dwarfed by the `fopen` syscall that produced them. If we ever
    /// hit a thousand-entry config we'll add `partition_point`.
    pub fn lookup(&self, key: &str) -> impl Iterator<Item = &Entry> + use<'_> {
        let folded = ascii_fold(key);
        self.entries.iter().filter(move |e| e.key_folded == folded)
    }

    /// All entries, in `config_compare` order. Useful for `tincctl`
    /// dump-config style output.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

// ────────────────────────────────────────────────────────────────────
// read_server_config
//
// ## What this is, what it isn't
//
// The C does three things in sequence:
//
//   1. read_config_options(tree, NULL)   ─ walk cmdline_conf, merge
//                                          dotless entries (-o Port=655)
//   2. read tinc.conf                    ─ hard fail if absent
//   3. opendir conf.d, readdir *.conf    ─ soft skip if dir absent,
//                                          hard fail if any file fails
//
// We port (2) and (3). (1) is a no-op for both fsck consumers and
// (eventually) the daemon's first call — cmdline_conf is populated
// only by `tincd -o` parsing in tincd.c:main(). The fsck binary
// (linked into tincctl, not tincd) sees an empty list. Checked: rg
// for cmdline_conf shows tincd.c, conf.c, conf.h — no tincctl.c.
//
// When the daemon lands and needs the cmdline merge, the calling
// pattern is `cfg.merge(cmdline_entries)` *before* calling this. The
// caller owns the cmdline list (it's argv-derived); this function
// doesn't reach for a global.
//
// ## The 40719189 mishap
//
// Upstream HEAD reads:
//
//     if(!dir && errno == ENOENT) {
//         return true;
//     } else {
//         logger(..., "Failed to read `%s'...", dname);
//         return false;
//     }
//
// When opendir SUCCEEDS, dir is non-NULL, !dir is false, the if
// fails, control falls to else, function returns false. The readdir
// loop at line 412 is unreachable. conf.d/ support has been broken
// since 2026-03-30 (commit 40719189, "Fix warnings from
// clang-tidy-23" — clang-tidy presumably flagged the old
// unset-errno-on-success path; the cure introduced this).
//
// We port the PRE-40719189 behavior (the 2017 logic, 9 years stable):
// dir absent for any reason → soft skip, dir present → read it.
// That's what every released tinc has done; that's what users have.
// The Rust IS the bugfix — we don't carry the regression.
//
// ## conf.d ordering
//
// readdir() returns entries in directory order (filesystem-
// dependent: ext4 is hash order, xfs is creation order). The C
// merges in readdir order. We sort. Rationale:
//
//   - The 4-tuple compare already sorts by (var, cmdline, line,
//     file), so two conf.d files defining the same key on different
//     lines are ordered by LINE first, not file. Merge order is
//     invisible there.
//   - Same key, same line number, different file: file name
//     tiebreaks. Merge order STILL invisible — the sort is total.
//   - The only place merge order leaks is Config::entries() (the
//     full dump). That's debug output.
//
// Sorting costs nothing (handful of files) and makes the dump
// deterministic across filesystems. The pre-40719189 C didn't sort
// because it didn't need to; we don't NEED to either, but readdir-
// order tests are flaky and we'd rather not.
//
// ## Why this lives in parse.rs not a new module
//
// It's the third caller of parse_file (after tinc-tools' get_my_name
// and load_host_pubkey). parse_file + merge are this module's bread
// and butter; this is just a directory loop on top. ~40 LOC of code,
// ~20 of it the conf.d glob.

/// `read_server_config` minus the cmdline merge.
///
/// Reads `<confbase>/tinc.conf`, then every `<confbase>/conf.d/*.conf`
/// (sorted by name), merging into a fresh [`Config`]. The cmdline
/// merge (`-o Port=655`) is NOT done here — caller owns that list and
/// can `cfg.merge(it)` separately. fsck doesn't have one.
///
/// `read_host_config` is intentionally NOT a function. It's two lines:
/// `cfg.merge(parse_file(confbase.join("hosts").join(name))?)`. Adding
/// a wrapper would obscure that the host file is just another file.
///
/// # Errors
///
/// - `tinc.conf` absent or unparseable → error. A daemon without a
///   tinc.conf has no Name.
/// - `conf.d/` absent → fine. Expected case (most installs don't
///   use it). Pre-40719189 C: any opendir failure is silently OK.
/// - `conf.d/` present but `read_dir` fails after open → error. C
///   wouldn't notice (`readdir()` returns NULL on error AND eof; the C
///   doesn't check errno after the loop). We're stricter — a
///   transient I/O error during fsck shouldn't read as "no findings."
/// - Any `*.conf` file in `conf.d/` unparseable → error.
pub fn read_server_config(confbase: impl AsRef<Path>) -> Result<Config, ReadError> {
    let confbase = confbase.as_ref();
    let mut cfg = Config::new();

    // (2) tinc.conf. Hard fail. parse_file already wraps the io error
    // with the path, so the error message says which file.
    cfg.merge(parse_file(confbase.join("tinc.conf"))?);

    // (3) conf.d/. Soft skip on absent dir.
    //
    // C condition is `if(dir)` — ANY opendir failure (ENOENT, EACCES,
    // ENOTDIR) is a silent skip in the pre-40719189 code. We match
    // that. If conf.d is a regular file or you can't read it, the
    // daemon starts anyway with just tinc.conf. Surprising? A bit. But
    // tightening it would make a Rust daemon refuse to start where a
    // 1.0.x daemon ran fine, on a config that's been working for years.
    // fsck can warn separately if it wants.
    let conf_d = confbase.join("conf.d");
    let Ok(rd) = std::fs::read_dir(&conf_d) else {
        return Ok(cfg);
    };

    // Collect-then-sort. See block comment above for why we sort and
    // the C doesn't (short version: merge order is invisible to lookup
    // because the 4-tuple compare is total; sorting just makes the
    // entries() dump deterministic).
    //
    // The filter: C does `l > 5 && !strcmp(".conf", name+l-5)`. The
    // strict `> 5` rejects a bare ".conf" (5 chars exactly) — you
    // need at least one character before the extension. ends_with
    // alone would accept it. The non-UTF-8 check is a side effect of
    // working in &str-land: a filename with non-UTF-8 bytes can't
    // pass strcmp(".conf", ...) in C either (the bytes wouldn't
    // match), so the behavior aligns.
    let mut files: Vec<PathBuf> = Vec::new();
    for ent in rd {
        // STRICTER: surface readdir errors instead of treating them
        // as eof. fsck reading a half-directory and saying
        // "all good" is the failure mode this prevents.
        let ent = ent.map_err(|err| ReadError::Io {
            path: conf_d.clone(),
            err,
        })?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else { continue };
        // CASE-SENSITIVE: `foo.CONF` is rejected. clippy's
        // "use Path::extension + eq_ignore_ascii_case" suggestion
        // would change behavior. Bytes-suffix is the port-faithful
        // form (and trivially also rejects non-ASCII look-alikes).
        #[expect(clippy::case_sensitive_file_extension_comparisons)] // tinc writes ".conf" exactly
        if name.len() > 5 && name.ends_with(".conf") {
            files.push(ent.path());
        }
    }
    files.sort();

    for f in files {
        cfg.merge(parse_file(f)?);
    }

    Ok(cfg)
}

/// `config_compare`. See [`Config`] doc for the 4-tuple breakdown.
fn compare_entries(a: &Entry, b: &Entry) -> Ordering {
    a.key_folded
        .cmp(&b.key_folded)
        .then_with(|| match (&a.source, &b.source) {
            // Cmdline < File.
            (Source::Cmdline { .. }, Source::File { .. }) => Ordering::Less,
            (Source::File { .. }, Source::Cmdline { .. }) => Ordering::Greater,
            // Within cmdline: line only.
            (Source::Cmdline { line: la }, Source::Cmdline { line: lb }) => la.cmp(lb),
            // Within file: line, then file path. C does `a->line - b->line`
            // first then `strcmp(file)` — line is the primary tiebreak,
            // *not* file. So `conf.d/a.conf:5` and `conf.d/b.conf:3`
            // sort by line (b.conf:3 first), not by filename.
            (Source::File { path: pa, line: la }, Source::File { path: pb, line: lb }) => {
                la.cmp(lb).then_with(|| pa.cmp(pb))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> Source {
        Source::File {
            path: "test".into(),
            line: 1,
        }
    }

    fn ok(line: &str) -> (String, String) {
        let e = parse_line(line, s()).unwrap().unwrap();
        (e.variable, e.value)
    }

    /// Separator grammar: all shapes parse identically. Covers `=`,
    /// space, ` = `, tabs, mixed-whitespace, and no-`=`.
    #[test]
    fn line_separator_forms() {
        for line in [
            "Port=655",
            "Port 655",
            "Port = 655",
            "Port\t=\t655",
            "Port \t  = \t  655",
            "Port\t655",
        ] {
            assert_eq!(ok(line), ("Port".into(), "655".into()), "{line:?}");
        }
    }

    /// `=` is in the strcspn set, so it terminates the variable even
    /// without surrounding whitespace.
    #[test]
    fn line_equals_terminates_variable() {
        assert_eq!(ok("a=b"), ("a".into(), "b".into()));
        // Second `=` is part of the value — only one optional `=` in
        // the separator.
        assert_eq!(ok("a==b"), ("a".into(), "=b".into()));
        assert_eq!(ok("a = =b"), ("a".into(), "=b".into()));
    }

    /// Trailing `\t` and ` ` stripped; other whitespace not.
    #[test]
    fn line_trailing_strip() {
        assert_eq!(ok("Port = 655   "), ("Port".into(), "655".into()));
        assert_eq!(ok("Port = 655\t\t"), ("Port".into(), "655".into()));
        // Newline is not in the strip set — readline already removed it.
        // If one sneaks through (shouldn't), it's part of the value.
        // We don't test that because `BufRead::lines()` guarantees it
        // doesn't happen.
    }

    /// Value can contain spaces — only the *separator's* spaces are eaten.
    #[test]
    fn line_value_with_spaces() {
        assert_eq!(ok("Name = my host"), ("Name".into(), "my host".into()));
        // Tabs too.
        assert_eq!(ok("X = a\tb"), ("X".into(), "a\tb".into()));
    }

    /// Empty value is the one error `parse_config_line` produces.
    #[test]
    fn line_empty_value_errors() {
        assert!(matches!(
            parse_line("Port", s()),
            Some(Err(ParseError {
                reason: "no value",
                ..
            }))
        ));
        assert!(matches!(parse_line("Port =", s()), Some(Err(_))));
        assert!(matches!(parse_line("Port = \t ", s()), Some(Err(_))));
    }

    /// Empty *variable* is not checked — C doesn't either.
    #[test]
    fn line_empty_variable_passes() {
        assert_eq!(ok("=x"), (String::new(), "x".into()));
        assert_eq!(ok(" = x"), (String::new(), "x".into()));
    }

    /// All-whitespace and empty lines: skip (None), not error.
    #[test]
    fn line_blank_skips() {
        assert!(parse_line("", s()).is_none());
        assert!(parse_line("   ", s()).is_none());
        assert!(parse_line("\t\t  \t", s()).is_none());
    }

    fn cfg(kvs: &[(&str, &str, Source)]) -> Config {
        let mut c = Config::new();
        c.merge(kvs.iter().map(|(k, v, s)| Entry {
            key_folded: ascii_fold(k),
            variable: (*k).to_owned(),
            value: (*v).to_owned(),
            source: s.clone(),
        }));
        c
    }

    fn file(p: &str, l: u32) -> Source {
        Source::File {
            path: p.into(),
            line: l,
        }
    }
    fn cmd(l: u32) -> Source {
        Source::Cmdline { line: l }
    }

    /// Lookup is case-insensitive (`strcasecmp`).
    #[test]
    fn lookup_case_insensitive() {
        let c = cfg(&[("Port", "655", file("f", 1))]);
        assert_eq!(c.lookup("port").next().unwrap().value, "655");
        assert_eq!(c.lookup("PORT").next().unwrap().value, "655");
        assert_eq!(c.lookup("PoRt").next().unwrap().value, "655");
    }

    /// Cmdline beats file. The `!b->file - !a->file` clause.
    #[test]
    fn lookup_cmdline_first() {
        let c = cfg(&[
            ("Port", "655", file("tinc.conf", 1)),
            ("Port", "656", cmd(1)),
        ]);
        // Inserted file-first; cmdline still wins.
        assert_eq!(c.lookup("Port").next().unwrap().value, "656");
    }

    /// Multi-valued keys iterate in file-line order.
    #[test]
    fn lookup_multi_ordered_by_line() {
        let c = cfg(&[
            ("Subnet", "10.0.2.0/24", file("hosts/foo", 5)),
            ("Subnet", "10.0.1.0/24", file("hosts/foo", 3)),
            ("Subnet", "10.0.0.0/24", cmd(1)),
        ]);
        let vals: Vec<_> = c.lookup("Subnet").map(|e| e.value.as_str()).collect();
        // cmdline → line 3 → line 5.
        assert_eq!(vals, ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]);
    }

    /// `conf.d/` corner case: same line number across files, filename
    /// tiebreaks. The `strcmp(a->file, b->file)` clause.
    #[test]
    fn lookup_file_tiebreak() {
        let c = cfg(&[
            ("X", "from-b", file("conf.d/b.conf", 1)),
            ("X", "from-a", file("conf.d/a.conf", 1)),
        ]);
        let vals: Vec<_> = c.lookup("X").map(|e| e.value.as_str()).collect();
        assert_eq!(vals, ["from-a", "from-b"]);
    }

    /// Line beats filename, even across files.
    #[test]
    fn lookup_line_before_file() {
        let c = cfg(&[
            ("X", "a-5", file("conf.d/a.conf", 5)),
            ("X", "b-3", file("conf.d/b.conf", 3)),
        ]);
        let vals: Vec<_> = c.lookup("X").map(|e| e.value.as_str()).collect();
        // b.conf line 3 sorts before a.conf line 5, despite filename order.
        assert_eq!(vals, ["b-3", "a-5"]);
    }

    fn entry(v: &str) -> Entry {
        Entry {
            key_folded: "x".into(),
            variable: "X".into(),
            value: v.into(),
            source: s(),
        }
    }

    #[test]
    fn entry_bool() {
        let e = entry;
        assert_eq!(e("yes").get_bool(), Ok(true));
        assert_eq!(e("YES").get_bool(), Ok(true));
        assert_eq!(e("Yes").get_bool(), Ok(true));
        assert_eq!(e("no").get_bool(), Ok(false));
        assert_eq!(e("NO").get_bool(), Ok(false));
        // Not accepted: anything else.
        assert!(e("true").get_bool().is_err());
        assert!(e("1").get_bool().is_err());
        assert!(e("y").get_bool().is_err());
        assert!(e("").get_bool().is_err());
    }

    /// `%d` semantics, with the trailing-garbage tightening.
    #[test]
    fn entry_int() {
        let e = entry;
        assert_eq!(e("655").get_int(), Ok(655));
        assert_eq!(e("-1").get_int(), Ok(-1));
        // Leading whitespace: `%d` accepts.
        assert_eq!(e("  655").get_int(), Ok(655));
        // Trailing garbage: STRICTER, we reject. Intentional tightening.
        assert!(e("655x").get_int().is_err());
        // Out of i32 range.
        assert!(e("99999999999").get_int().is_err());
        // Not a number at all.
        assert!(e("foo").get_int().is_err());
    }

    /// PEM blocks in the input are stepped over.
    #[test]
    fn file_skips_pem() {
        let input = "\
Address = 1.2.3.4
Port = 655
-----BEGIN ED25519 PUBLIC KEY-----
IBazFooBarBazQux+/0123456789ABCDEFGHIJKabcd
-----END ED25519 PUBLIC KEY-----
Subnet = 10.0.0.0/24
";
        let entries = parse_reader(input.as_bytes(), Path::new("hosts/foo")).unwrap();
        let kvs: Vec<_> = entries
            .iter()
            .map(|e| (e.variable.as_str(), e.value.as_str()))
            .collect();
        assert_eq!(
            kvs,
            [
                ("Address", "1.2.3.4"),
                ("Port", "655"),
                ("Subnet", "10.0.0.0/24")
            ]
        );
    }

    /// Comment and blank lines skipped, line numbers still tick.
    #[test]
    fn file_comments_and_blanks() {
        let input = "\
# this is a comment
Port = 655

# another
Subnet = 10.0.0.0/24
";
        let entries = parse_reader(input.as_bytes(), Path::new("f")).unwrap();
        assert_eq!(entries.len(), 2);
        // Port is on line 2, Subnet on line 5.
        assert!(matches!(entries[0].source, Source::File { line: 2, .. }));
        assert!(matches!(entries[1].source, Source::File { line: 5, .. }));
    }

    /// CRLF handled by `BufRead::lines()`.
    #[test]
    fn file_crlf() {
        let input = "Port = 655\r\nSubnet = 10.0.0.0/24\r\n";
        let entries = parse_reader(input.as_bytes(), Path::new("f")).unwrap();
        assert_eq!(entries[0].value, "655"); // not "655\r"
    }

    /// Unterminated PEM: no `-----END`. C just runs to EOF in ignore
    /// mode. We do too.
    #[test]
    fn file_pem_unterminated() {
        let input = "\
Port = 655
-----BEGIN FOO-----
garbage
more garbage
";
        let entries = parse_reader(input.as_bytes(), Path::new("f")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].variable, "Port");
    }

    // read_server_config — directory tests need a real filesystem.
    // tempdir layouts are cheap; each test builds the exact tree it
    // checks. No fixture sharing — hermetic per-test.

    /// Unique tempdir, removed on drop. Same pattern as
    /// `tinc-tools::cmd::genkey::TmpGuard`, smaller.
    struct Td(PathBuf);
    impl Td {
        fn new(tag: &str) -> Self {
            // Unique by test name + thread id. Tests run parallel by
            // default; a fixed name races.
            let p = std::env::temp_dir()
                .join(format!("tinc_conf_{tag}_{:?}", std::thread::current().id()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn join(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
    }
    impl Drop for Td {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: impl AsRef<Path>, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    /// The common case: just tinc.conf, no conf.d/. Matches every
    /// `tinc init`-produced layout (init doesn't make conf.d/).
    #[test]
    fn server_no_confd() {
        let td = Td::new("no_confd");
        write(td.join("tinc.conf"), "Name = alice\nPort = 655\n");

        let cfg = read_server_config(&td.0).unwrap();
        assert_eq!(cfg.lookup("Name").next().unwrap().value, "alice");
        assert_eq!(cfg.lookup("Port").next().unwrap().value, "655");
        assert_eq!(cfg.entries().len(), 2);
    }

    /// tinc.conf absent → hard fail. C logs the path + strerror,
    /// daemon exits.
    #[test]
    fn server_no_tincconf() {
        let td = Td::new("no_tc");
        // Empty dir, no tinc.conf.
        let err = read_server_config(&td.0).unwrap_err();
        // ReadError::Io carries the path. Check it's the right file.
        let ReadError::Io { path, .. } = err else {
            panic!("expected Io error")
        };
        assert!(path.ends_with("tinc.conf"));
    }

    /// conf.d/ with two files. Both merged. Multi-value key spans
    /// tinc.conf and conf.d — lookup iterates all three.
    #[test]
    fn server_confd_merged() {
        let td = Td::new("merged");
        write(td.join("tinc.conf"), "Name = alice\nConnectTo = bob\n");
        std::fs::create_dir(td.join("conf.d")).unwrap();
        write(td.join("conf.d/10-one.conf"), "ConnectTo = carol\n");
        write(td.join("conf.d/20-two.conf"), "ConnectTo = dave\n");

        let cfg = read_server_config(&td.0).unwrap();
        let connects: Vec<_> = cfg.lookup("ConnectTo").map(|e| e.value.as_str()).collect();
        // Three values total. Order: tinc.conf:2 (bob), then conf.d
        // files at line 1 each. Per the 4-tuple, line-before-file:
        // both conf.d entries are line 1, so file name tiebreaks →
        // 10-one before 20-two. THEN tinc.conf line 2 (higher line).
        //
        // The compare is line-then-file, not file-then-line, so
        // conf.d/*.conf:1 sorts before tinc.conf:2. Surprising but
        // protocol-faithful; fsck can warn someday.
        assert_eq!(connects, ["carol", "dave", "bob"]);
    }

    /// Non-.conf files in conf.d/ are ignored. Including a sneaky
    /// `.conf.bak` (suffix doesn't match) and bare `.conf` (len 5,
    /// fails the `> 5` check).
    #[test]
    fn server_confd_filter() {
        let td = Td::new("filter");
        write(td.join("tinc.conf"), "Name = alice\n");
        std::fs::create_dir(td.join("conf.d")).unwrap();
        write(td.join("conf.d/real.conf"), "Port = 655\n");
        write(td.join("conf.d/backup.conf.bak"), "Port = 999\n");
        write(td.join("conf.d/README"), "Port = 888\n");
        // The `> 5` boundary: a file literally named ".conf".
        write(td.join("conf.d/.conf"), "Port = 777\n");

        let cfg = read_server_config(&td.0).unwrap();
        // Only real.conf's Port. The other three are filtered.
        let ports: Vec<_> = cfg.lookup("Port").map(|e| e.value.as_str()).collect();
        assert_eq!(ports, ["655"]);
    }

    /// Empty conf.d/. Directory exists but contains nothing. Same as
    /// absent for our purposes — no files to merge, no error.
    #[test]
    fn server_confd_empty() {
        let td = Td::new("empty");
        write(td.join("tinc.conf"), "Name = alice\n");
        std::fs::create_dir(td.join("conf.d")).unwrap();

        let cfg = read_server_config(&td.0).unwrap();
        assert_eq!(cfg.entries().len(), 1);
    }

    /// One bad file in conf.d/ fails the whole read. C: hard fail.
    /// The good file merged before the bad one is lost — we discard
    /// partial results (see [`parse_file`] docs).
    #[test]
    fn server_confd_one_bad() {
        let td = Td::new("one_bad");
        write(td.join("tinc.conf"), "Name = alice\n");
        std::fs::create_dir(td.join("conf.d")).unwrap();
        write(td.join("conf.d/10-good.conf"), "Port = 655\n");
        // Missing value — parse error.
        write(td.join("conf.d/20-bad.conf"), "Port\n");

        // Sorted order: 10-good reads first (succeeds, merges), then
        // 20-bad fails. Result is Err; the merged Port is gone.
        let err = read_server_config(&td.0).unwrap_err();
        assert!(matches!(err, ReadError::Parse(_)));
    }

    /// **The 40719189 regression test.** conf.d/ exists AND has a
    /// file — if we'd ported HEAD's C, this would fail (the C
    /// returns false the moment opendir succeeds). It passing proves
    /// we ported the pre-40719189 (working) behavior.
    ///
    /// This is the same setup as `server_confd_merged` but reduced to
    /// the minimum that demonstrates the bug. Kept separate so the
    /// test name is the documentation.
    #[test]
    fn server_confd_head_bug_not_ported() {
        let td = Td::new("head_bug");
        write(td.join("tinc.conf"), "Name = alice\n");
        std::fs::create_dir(td.join("conf.d")).unwrap();
        write(td.join("conf.d/a.conf"), "Port = 655\n");

        let cfg = read_server_config(&td.0).unwrap();
        // The kill shot: HEAD C would have returned false before the
        // readdir loop, never reading a.conf. We did read it.
        assert_eq!(cfg.lookup("Port").next().unwrap().value, "655");
    }

    /// conf.d is a regular file, not a directory. Pre-40719189 C:
    /// opendir returns NULL with ENOTDIR, `if(dir)` fails, silent
    /// skip. We match. (HEAD C: !dir is true, errno is ENOTDIR not
    /// ENOENT, falls to else, return false. Another way 40719189
    /// broke things.)
    #[test]
    fn server_confd_is_file() {
        let td = Td::new("is_file");
        write(td.join("tinc.conf"), "Name = alice\n");
        // conf.d as a file. Weird but not malicious — someone
        // ran `echo > conf.d` by accident.
        write(td.join("conf.d"), "this is not a directory\n");

        let cfg = read_server_config(&td.0).unwrap();
        assert_eq!(cfg.entries().len(), 1); // just Name
    }
}
