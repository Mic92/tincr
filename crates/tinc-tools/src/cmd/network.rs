//! `tinc network` — list configured networks under `confdir`.
//!
//! C: `tincctl.c:2690-2730` + `switch_network` (`:2658-2688`).
//!
//! ## Two modes; we port one
//!
//! `tinc network` (argless) → LIST: scan `confdir` for subdirs with
//! `tinc.conf`. `tinc network NAME` → SWITCH: mutate `netname`/
//! `confbase`/`prompt` globals. SWITCH only matters in the C's
//! readline loop (`tincctl.c:3195-3264`); we have no readline loop,
//! so it'd mutate globals and EXIT. **Deliberate C-behavior-drop #2.**
//! The error message says "use `-n NAME` instead."
//!
//! ## The LIST mode
//!
//! `tincctl.c:2700-2727`:
//!
//! ```text
//!   opendir(confdir)             ← /etc/tinc
//!   for each entry:
//!     if name starts with '.':   ← :2710  skip .  ..  .git  etc
//!       skip
//!     if name == "tinc.conf":    ← :2714  no-netname case
//!       print "."                  (the "default network" sentinel)
//!     else:
//!       if confdir/name/tinc.conf is readable:  ← :2722 access(R_OK)
//!         print name
//! ```
//!
//! The `.` sentinel (`:2714-2717`): when `confdir == confbase` (no
//! `-n`/`-c`), `tinc.conf` lives directly in `/etc/tinc` — the
//! "anonymous" network. C prints `.` (switch-target `:2676`:
//! `netname = NULL`). For us `.` is just a label.
//!
//! ## confdir resolution
//!
//! The C `confdir` is ALWAYS set (`names.c:86`: `confdir = xstrdup(
//! CONFDIR "/tinc")` unconditional, even with `-c`). Our `Paths::
//! confdir` is `Option` — `None` when `-c` was given (makedirs
//! doesn't need the parent then). `Paths::confdir_always()` papers
//! over: synthesizes `CONFDIR/tinc` for the `None` case.
//!
//! `tinc -c /foo network` thus reads `/etc/tinc`, not `/foo/..`.
//! Same as C. Correct: `-c` names ONE confbase, not a directory
//! of confbases. The list is "all networks the system knows about,"
//! orthogonal to which one this invocation is configured for.
//!
//! ## Ordering
//!
//! C uses `readdir` order (undefined). We sort: any order is
//! C-compatible since C's is undefined, and sorted is deterministic
//! for tests. `.` floats to top (ASCII `.` < letters).

#![allow(clippy::doc_markdown)]

use std::io::{self, Write};
use std::path::Path;

use crate::names::Paths;

use super::CmdError;

// List

/// `tincctl.c:2700-2727` — scan `confdir`, emit network names.
///
/// Separate from `run()` so tests can pass an arbitrary dir
/// (the real `confdir_always()` is `/etc/tinc`, which the test
/// runner can't write to).
///
/// Writes to `out`, not `stdout`, for the same reason. The names
/// are `\n`-separated. The C `printf("%s\n")` does the same.
///
/// Returns the COUNT for tests. The C doesn't (it just prints);
/// we don't either at the CLI surface (the caller drops the count).
///
/// # Errors
/// `read_dir` failing — `Io { path: confdir, err }`. Missing
/// `/etc/tinc` is `ENOENT` here. The C `opendir` failing
/// (`:2702-2705`) does the same.
///
/// `write_all` failing — also `Io`, but with `<stdout>` sentinel
/// path. SIGPIPE if piped to `head`. The lib's `signal(SIGPIPE,
/// SIG_IGN)` means we get the error, not the signal; bubbles up;
/// exits nonzero. C `printf` ignores the error (`:2716,2724`),
/// keeps printing into the void. Ours is stricter (stops on
/// EPIPE); fine.
pub(crate) fn list(confdir: &Path, out: &mut impl Write) -> Result<usize, CmdError> {
    use super::io_err;

    // Collect first, sort, then print. The C prints as it iterates
    // (no sort). Sorting needs the full list in memory. The number
    // of networks on a host is single-digit; the buffer is
    // negligible.
    let mut found: Vec<String> = Vec::new();

    // ─── readdir loop
    // `tincctl.c:2709-2726`. The C `while((ent = readdir(dir)))`.
    // `read_dir` returns `io::Result<ReadDir>`; `ReadDir` is an
    // iterator over `io::Result<DirEntry>`.
    let entries = std::fs::read_dir(confdir).map_err(io_err(confdir))?;
    for ent in entries {
        // Per-entry I/O error. Rare (the dir moved out from under
        // us mid-iteration?). The C `readdir` would return NULL
        // and set errno; the C loop breaks on NULL (the `while`
        // condition); the error is lost. We propagate.
        let ent = ent.map_err(io_err(confdir))?;
        let name = ent.file_name();

        // `tincctl.c:2710`: `if(*ent->d_name == '.')`. STARTS-WITH,
        // not equals. Skips `.`, `..`, AND `.git`, `.hidden`, etc.
        // The C is more permissive about what `confdir` contains
        // than you'd expect (people version-control it).
        //
        // `OsStr` doesn't have `starts_with` for chars. `as_encoded_
        // bytes()` is the no-alloc way: `[0] == b'.'`. Safe — the
        // bytes are an OPAQUE encoding but the docs guarantee
        // ASCII subrange is verbatim.
        let name_bytes = name.as_encoded_bytes();
        if name_bytes.first() == Some(&b'.') {
            continue;
        }

        // `tincctl.c:2714`: `if(!strcmp(ent->d_name, "tinc.conf"))`.
        // The `tinc.conf` directly in `confdir` is the anonymous
        // network (no `-n`). Record `.` for it.
        //
        // `OsStr == &str` comparison. Works (`PartialEq<&str>`
        // for `OsStr`). UTF-8-only equality; `"tinc.conf"` is
        // pure ASCII so always matches itself byte-for-byte.
        if name == "tinc.conf" {
            // `tincctl.c:2716`: `printf(".\n")`.
            // The `.` is the "switch back to no-netname" sentinel
            // for the C's readline mode. For us it's just a label.
            found.push(".".to_owned());
            continue;
        }

        // `tincctl.c:2720-2724`: `confdir/name/tinc.conf` readable?
        // `access(R_OK)` is "would open() with O_RDONLY succeed?"
        // — checks existence + readable + (if dir, traverse perms).
        //
        // `Path::is_file()` is NOT the same: it's `stat` then check
        // `S_ISREG`. Doesn't check readability. A `tinc.conf` with
        // `chmod 000` would pass `is_file()` but fail `access(R_OK)`.
        // The C says "can I read it"; `is_file` says "is it a file."
        //
        // Match C: `nix::unistd::access`. Already a dep. The
        // `AccessFlags::R_OK` constant matches `R_OK` from `<unistd.h>`.
        // Returns `Err` for any failure (ENOENT, EACCES, ELOOP) —
        // same as the C `if(!access(...))` test (`access` returns
        // 0 on success, -1 on failure; C's `!access` is "succeeded").
        //
        // ACTUALLY: simpler. `fs::File::open()` is exactly "can I
        // open for reading?" (default mode). Succeeds → readable.
        // No `nix` needed; `std` does it. The open is one syscall
        // more than `access` (and creates an fd we immediately
        // drop) but it's CORRECT (no TOCTOU concern; we're not
        // using the result anyway, just probing). The semantics are
        // identical for our purposes: can-read.
        //
        // … no, wait. `access(R_OK)` checks against the REAL uid,
        // `open()` against the EFFECTIVE uid. setuid binaries see
        // different results. We're not setuid (and never will be —
        // tinc CLI as setuid would be insane). Same answer.
        let probe = confdir.join(&name).join("tinc.conf");
        if std::fs::File::open(&probe).is_ok() {
            // Convert `OsString` → `String` for printing. Lossy:
            // a netname with non-UTF-8 bytes would `?` replace.
            // The C `printf("%s")` would print the raw bytes (which
            // might mangle the terminal but wouldn't lose data on
            // pipe). We lose data on `?` — tradeoff for `String`.
            //
            // BUT: `netname` validation (`check_netname` in C,
            // `tincctl.c:108-126`) only allows alnum + `_` (strict)
            // or printable ASCII minus shell-hazards (loose). All
            // ASCII. A non-UTF-8 dir name in `confdir` is "someone
            // mkdir'd a weird name," not a tinc-created network.
            // The lossy print is fine. (The C would print it; we'd
            // `?` it; neither would actually USE it as a netname.)
            found.push(name.to_string_lossy().into_owned());
        }
        // ELSE: not a network dir. `confdir/README`, `confdir/
        // backup.tar`, whatever. Silent skip. C does the same
        // (`:2722` is the only `printf`; non-match is no-op).
    }

    // ─── Sort & emit
    // NOT in C. C readdir-order is undefined; sorted is in the set
    // of valid C outputs. Deterministic for tests.
    //
    // `.` sorts first (`.` is 0x2E, less than `0` (0x30) and `A`
    // (0x41)). The anonymous network at the top is also a nice
    // order — it's the "default."
    found.sort_unstable();

    for name in &found {
        // `printf("%s\n")`. `writeln!` adds the `\n`.
        writeln!(out, "{name}").map_err(|e| CmdError::Io {
            // `<stdout>` sentinel — the write failure isn't a
            // file path failure. SIGPIPE → EPIPE → here.
            path: std::path::PathBuf::from("<stdout>"),
            err: e,
        })?;
    }

    Ok(found.len())
}

// CLI entry

/// `tinc network [NAME]`. List mode or error-with-advice.
///
/// `tincctl.c:2690-2698` for the dispatch; `:2700-2727` is `list()`.
///
/// `arg`: `None` → list. `Some(name)` → would-be-switch.
///
/// # Errors
/// `BadInput` for the switch-mode (with "use -n NAME" message). `Io`
/// for `read_dir` failures.
pub fn run(paths: &Paths, arg: Option<&str>) -> Result<(), CmdError> {
    if let Some(name) = arg {
        // ─── SWITCH mode — deliberate C-behavior-drop #2
        // C `tincctl.c:2697`: `return switch_network(argv[1])`.
        // `switch_network` (`:2658-2688`) closes the daemon socket,
        // frees+reallocs `netname`/`confbase`/`prompt`, returns 0.
        // The mutation only matters if the readline loop continues.
        //
        // We have no readline. The mutation would happen, then `Ok
        // (())` → exit 0. Silent no-op. WORSE than erroring: the
        // user thinks something happened.
        //
        // The error message says what to do. `tinc -n NAME ...` is
        // the equivalent. (Or shell `export NETNAME=...` for
        // sticky.) The C help text (`tincctl.c:197`) says "switch
        // to the one named NETNAME" — that's a readline-loop
        // promise we can't keep.
        //
        // The `.` sentinel: C `:2676` maps it to `netname = NULL`.
        // We mention "no -n" for `.`. The user reading `tinc
        // network` output sees `.`, runs `tinc network .`, gets
        // told the right thing.
        let how = if name == "." {
            "use `tinc COMMAND` (no -n) to act on the default network"
        } else {
            "use `tinc -n NAME COMMAND` instead"
        };
        return Err(CmdError::BadInput(format!(
            "Network switching requires the interactive shell, which the Rust port doesn't have; {how}."
        )));
    }

    // ─── LIST mode
    // `confdir_always()` materializes the C's "always set" — falls
    // back to `/etc/tinc` even when `-c` was given. See module doc.
    let confdir = paths.confdir_always();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    list(&confdir, &mut out)?;
    Ok(())
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Unique tempdir per test. Same idiom as the other modules:
    /// test name + thread ID, parallel-safe. Dropped at scope end
    /// via `TempDir`'s `Drop`.
    fn tmpdir(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!(
                "tinc-network-{name}-{:?}-",
                std::thread::current().id()
            ))
            .tempdir()
            .unwrap()
    }

    /// Create `dir/NAME/tinc.conf`. The probe in `list()` opens
    /// this for reading; content doesn't matter.
    fn mknet(dir: &Path, name: &str) {
        let d = dir.join(name);
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("tinc.conf"), "").unwrap();
    }

    // list — the readdir scan

    /// Empty `confdir` → empty output, count 0. The `read_dir`
    /// loop body never enters.
    #[test]
    fn list_empty() {
        let d = tmpdir("empty");
        let mut out = Vec::new();
        let n = list(d.path(), &mut out).unwrap();
        assert_eq!(n, 0);
        assert!(out.is_empty());
    }

    /// Three networks → three lines, sorted. Pins the sort (NOT in
    /// C; readdir order is undefined). `.` not present (no top-
    /// level `tinc.conf`).
    #[test]
    fn list_three_sorted() {
        let d = tmpdir("three");
        // Create in NON-sorted order to prove the sort happens.
        mknet(d.path(), "bravo");
        mknet(d.path(), "alpha");
        mknet(d.path(), "charlie");

        let mut out = Vec::new();
        let n = list(d.path(), &mut out).unwrap();
        assert_eq!(n, 3);
        assert_eq!(out, b"alpha\nbravo\ncharlie\n");
    }

    /// `tinc.conf` directly in `confdir` → `.` in output.
    /// `tincctl.c:2714-2717`: the anonymous-network sentinel.
    /// `.` sorts first (0x2E < letters).
    #[test]
    fn list_anonymous_network() {
        let d = tmpdir("anon");
        // Top-level tinc.conf → `.`
        std::fs::write(d.path().join("tinc.conf"), "").unwrap();
        mknet(d.path(), "vpn");

        let mut out = Vec::new();
        let n = list(d.path(), &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(out, b".\nvpn\n");
    }

    /// Dotted entries skipped. `tincctl.c:2710`: `if(*ent->d_name
    /// == '.')`. `.git`, `.backup`, `.` (the dirent), `..` — all
    /// start with `.`, all skipped.
    ///
    /// `.git/tinc.conf` would otherwise be a "network named .git."
    /// The C skip handles it. (read_dir DOESN'T yield `.` and `..`
    /// — POSIX `readdir` does; Rust filters them. The dot-prefix
    /// check is for `.git`-shaped entries.)
    #[test]
    fn list_skip_dotted() {
        let d = tmpdir("dotted");
        mknet(d.path(), "vpn");
        // `.git` dir with a tinc.conf — version control of confdir.
        mknet(d.path(), ".git");
        // `.backup` — same shape.
        mknet(d.path(), ".backup");

        let mut out = Vec::new();
        let n = list(d.path(), &mut out).unwrap();
        // Only `vpn`. The dotted ones don't count.
        assert_eq!(n, 1);
        assert_eq!(out, b"vpn\n");
    }

    /// Directory WITHOUT `tinc.conf` → not listed. `tincctl.c
    /// :2722`: `if(!access(...))` — `access` fails ENOENT.
    /// Silent skip.
    #[test]
    fn list_skip_no_tinc_conf() {
        let d = tmpdir("notinc");
        mknet(d.path(), "real");
        // `garbage` exists but has no tinc.conf.
        std::fs::create_dir(d.path().join("garbage")).unwrap();

        let mut out = Vec::new();
        let n = list(d.path(), &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out, b"real\n");
    }

    /// Regular FILE (not dir) in `confdir` → not listed.
    /// `confdir/README/tinc.conf` doesn't exist (README is a
    /// file, not a dir; `join` produces a path that `open()` fails
    /// on with ENOTDIR). C `access(R_OK)` fails the same way.
    #[test]
    fn list_skip_regular_files() {
        let d = tmpdir("files");
        mknet(d.path(), "vpn");
        std::fs::write(d.path().join("README"), "hi").unwrap();
        std::fs::write(d.path().join("backup.tar"), "").unwrap();

        let mut out = Vec::new();
        let n = list(d.path(), &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out, b"vpn\n");
    }

    /// `tinc.conf` unreadable → not listed. The `access(R_OK)` /
    /// `File::open()` distinction. `chmod 000` makes it exist but
    /// fail open. C `access` returns -1 (EACCES); our `open`
    /// returns `Err` (PermissionDenied). Same skip.
    ///
    /// SKIP under root: root reads `chmod 000` files (DAC
    /// override). The test would pass with `n=2` not `n=1`. CI
    /// doesn't run as root; local `cargo test` might (in a
    /// container). Gate on euid.
    #[test]
    #[cfg(unix)]
    fn list_skip_unreadable() {
        use std::os::unix::fs::PermissionsExt;

        // Root reads anything. Skip. (`nix::unistd::geteuid` is
        // always-on, no feature gate needed.)
        if nix::unistd::geteuid().is_root() {
            eprintln!("(skipping list_skip_unreadable: running as root)");
            return;
        }

        let d = tmpdir("unreadable");
        mknet(d.path(), "ok");
        mknet(d.path(), "noread");
        // Strip all perms. `set_permissions` is `chmod`.
        let target = d.path().join("noread").join("tinc.conf");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();

        let mut out = Vec::new();
        let n = list(d.path(), &mut out).unwrap();
        assert_eq!(n, 1, "only `ok` should pass; `noread` fails open");
        assert_eq!(out, b"ok\n");

        // Restore for the tempdir Drop (chmod 000 file in a
        // tempdir — `remove_dir_all` would fail to unlink it on
        // some systems? Actually unlink only needs WRITE on the
        // PARENT dir. The file's own perms don't block unlink.
        // But restore anyway; principle of least surprise for
        // future-you reading test failures.)
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// Nonexistent `confdir` → `Io` error. `tincctl.c:2702-2705`:
    /// `opendir` fails, fprintf stderr, return 1.
    #[test]
    fn list_missing_confdir() {
        let mut out = Vec::new();
        let e = list(Path::new("/nonexistent/tinc-test-dir"), &mut out).unwrap_err();
        assert!(matches!(e, CmdError::Io { .. }));
    }

    // run — the switch-mode rejection

    /// `tinc network NAME` → error with `-n` advice. Deliberate
    /// C-behavior-drop #2.
    #[test]
    fn run_switch_rejected() {
        let p = crate::names::Paths::for_cli(&crate::names::PathsInput {
            confbase: Some(PathBuf::from("/tmp/test")),
            ..Default::default()
        });
        let e = run(&p, Some("foo")).unwrap_err();
        let CmdError::BadInput(msg) = e else {
            panic!("expected BadInput, got {e:?}");
        };
        // The advice — what to do INSTEAD.
        assert!(msg.contains("-n"), "msg: {msg}");
    }

    /// `tinc network .` → DIFFERENT advice (no -n, not "-n .").
    /// `.` means "the anonymous/default network" — `tinc COMMAND`
    /// without -n is how you reach it.
    #[test]
    fn run_switch_dot_different_advice() {
        let p = crate::names::Paths::for_cli(&crate::names::PathsInput {
            confbase: Some(PathBuf::from("/tmp/test")),
            ..Default::default()
        });
        let e = run(&p, Some(".")).unwrap_err();
        let CmdError::BadInput(msg) = e else {
            panic!("expected BadInput, got {e:?}");
        };
        // "no -n" or "default" — the message distinguishes.
        assert!(
            msg.contains("no -n") || msg.contains("default"),
            "msg: {msg}"
        );
        // NOT the generic `-n NAME` advice.
        assert!(!msg.contains("-n NAME"), "msg: {msg}");
    }
}
