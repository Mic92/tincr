//! `tinc network` — list configured networks under `confdir`.
//!
//! ## Two modes; we port one
//!
//! `tinc network` (argless) → LIST: scan `confdir` for subdirs with
//! `tinc.conf`. `tinc network NAME` → SWITCH: only meaningful in an
//! interactive readline loop, which we don't have. **Deliberate
//! upstream-behavior-drop #2.** The error message says "use `-n
//! NAME` instead."
//!
//! ## The LIST mode
//!
//! ```text
//!   opendir(confdir)             ← /etc/tinc
//!   for each entry:
//!     if name starts with '.':   skip .  ..  .git  etc
//!       skip
//!     if name == "tinc.conf":    no-netname case
//!       print "."                (the "default network" sentinel)
//!     else:
//!       if confdir/name/tinc.conf is readable:
//!         print name
//! ```
//!
//! The `.` sentinel: when `confdir == confbase` (no `-n`/`-c`),
//! `tinc.conf` lives directly in `/etc/tinc` — the "anonymous"
//! network. For us `.` is just a label.
//!
//! ## confdir resolution
//!
//! `Paths::confdir_always()` synthesizes `CONFDIR/tinc` even when
//! `-c` was given. `tinc -c /foo network` thus reads `/etc/tinc`,
//! not `/foo/..`. Correct: `-c` names ONE confbase, not a directory
//! of confbases. The list is "all networks the system knows about,"
//! orthogonal to which one this invocation is configured for.
//!
//! ## Ordering
//!
//! We sort. Upstream uses `readdir` order (undefined), so sorted is
//! still compatible, and it's deterministic for tests. `.` floats
//! to top (ASCII `.` < letters).

#![allow(clippy::doc_markdown)]

use std::io::{self, Write};
use std::path::Path;

use crate::names::Paths;

use super::CmdError;

// List

/// Scan `confdir`, emit network names.
///
/// Separate from `run()` so tests can pass an arbitrary dir
/// (the real `confdir_always()` is `/etc/tinc`, which the test
/// runner can't write to). Writes to `out` for the same reason.
///
/// Returns the COUNT for tests; the CLI surface drops it.
///
/// # Errors
/// `read_dir` failing — `Io { path: confdir, err }`. Missing
/// `/etc/tinc` is `ENOENT` here.
///
/// `write_all` failing — also `Io`, with `<stdout>` sentinel path.
/// SIGPIPE if piped to `head` becomes EPIPE; we stop. Upstream
/// keeps printing into the void; ours is stricter. Fine.
pub(crate) fn list(confdir: &Path, out: &mut impl Write) -> Result<usize, CmdError> {
    use super::io_err;

    // Collect first, sort, then print. The number of networks on a
    // host is single-digit; the buffer is negligible.
    let mut found: Vec<String> = Vec::new();

    let entries = std::fs::read_dir(confdir).map_err(io_err(confdir))?;
    for ent in entries {
        // Per-entry I/O error. Rare (the dir moved out from under
        // us mid-iteration?). We propagate.
        let ent = ent.map_err(io_err(confdir))?;
        let name = ent.file_name();

        // STARTS-WITH `.`, not equals. Skips `.`, `..`, AND `.git`,
        // `.hidden`, etc. (people version-control confdir).
        //
        // `OsStr` doesn't have `starts_with` for chars. `as_encoded_
        // bytes()` is the no-alloc way: `[0] == b'.'`. Safe — the
        // bytes are opaque but ASCII subrange is verbatim.
        let name_bytes = name.as_encoded_bytes();
        if name_bytes.first() == Some(&b'.') {
            continue;
        }

        // `tinc.conf` directly in `confdir` is the anonymous
        // network (no `-n`). Record `.` for it.
        if name == "tinc.conf" {
            found.push(".".to_owned());
            continue;
        }

        // `confdir/name/tinc.conf` readable? `fs::File::open()` is
        // exactly "can I open for reading?" — succeeds → readable.
        // (`access(R_OK)` checks REAL uid, `open()` checks EFFECTIVE
        // uid; we're not setuid so same answer.)
        let probe = confdir.join(&name).join("tinc.conf");
        if std::fs::File::open(&probe).is_ok() {
            // Lossy conversion: a non-UTF-8 dir name in `confdir`
            // is "someone mkdir'd a weird name," not a tinc-created
            // network (netname validation is ASCII-only). The lossy
            // print is fine; neither end would USE it as a netname.
            found.push(name.to_string_lossy().into_owned());
        }
        // ELSE: not a network dir. `confdir/README`, `confdir/
        // backup.tar`, whatever. Silent skip.
    }

    // ─── Sort & emit
    // `.` sorts first (0x2E < `0` and `A`). The anonymous network
    // at the top is a nice order — it's the "default."
    found.sort_unstable();

    for name in &found {
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
/// `arg`: `None` → list. `Some(name)` → would-be-switch.
///
/// # Errors
/// `BadInput` for the switch-mode (with "use -n NAME" message). `Io`
/// for `read_dir` failures.
pub fn run(paths: &Paths, arg: Option<&str>) -> Result<(), CmdError> {
    if let Some(name) = arg {
        // ─── SWITCH mode — deliberate upstream-behavior-drop #2
        // We have no readline loop. The mutation would happen, then
        // `Ok(())` → exit 0. Silent no-op — WORSE than erroring:
        // the user thinks something happened.
        //
        // The error message says what to do instead. The user
        // reading `tinc network` output sees `.`, runs `tinc
        // network .`, gets told the right thing.
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
    // `confdir_always()` falls back to `/etc/tinc` even when `-c`
    // was given. See module doc.
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

    /// Three networks → three lines, sorted. `.` not present (no
    /// top-level `tinc.conf`).
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

    /// `tinc.conf` directly in `confdir` → `.` in output (the
    /// anonymous-network sentinel). `.` sorts first (0x2E < letters).
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

    /// Dotted entries skipped. `.git`, `.backup` — all start with
    /// `.`, all skipped. `.git/tinc.conf` would otherwise be a
    /// "network named .git." (`read_dir` doesn't yield `.`/`..`;
    /// the dot-prefix check is for `.git`-shaped entries.)
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

    /// Directory WITHOUT `tinc.conf` → not listed. Silent skip.
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
    /// file, not a dir; `open()` fails with ENOTDIR).
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

    /// `tinc.conf` unreadable → not listed. `chmod 000` makes it
    /// exist but fail open with PermissionDenied. Same skip.
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

    /// Nonexistent `confdir` → `Io` error.
    #[test]
    fn list_missing_confdir() {
        let mut out = Vec::new();
        let e = list(Path::new("/nonexistent/tinc-test-dir"), &mut out).unwrap_err();
        assert!(matches!(e, CmdError::Io { .. }));
    }

    // run — the switch-mode rejection

    /// `tinc network NAME` → error with `-n` advice. Deliberate
    /// upstream-behavior-drop #2.
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
