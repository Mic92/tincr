//! `tinc edit FILE` — spawn `$VISUAL`/`$EDITOR`/`vi` on a config
//! file, then silently signal the daemon to reload.
//!
//! ## The path-resolution lattice
//!
//! `cmd_edit`'s input is a SHORTHAND, not a path — the point is
//! `tinc edit tinc.conf` instead of `vi /etc/tinc/foo/tinc.conf`.
//!
//! ```text
//!   conffiles[] = {"tinc.conf", "tinc-up", ..., NULL};
//!
//!   if (input doesn't start with "hosts/"):
//!     for f in conffiles:
//!       if input == f: filename = confbase/f
//!   else:
//!     input += 6  (strip "hosts/")
//!
//!   if filename still empty:
//!     filename = hosts_dir/input
//!     if input contains '-':
//!       split at first '-'
//!       require suffix ∈ {"up","down"} AND check_id(prefix)
//! ```
//!
//! Four cases:
//!
//! | input            | resolves to            | validation              |
//! |------------------|------------------------|-------------------------|
//! | `"tinc.conf"`    | `confbase/tinc.conf`   | conffiles[] membership  |
//! | `"hosts/alice"`  | `hosts_dir/alice`      | NONE (after strip)      |
//! | `"alice"`        | `hosts_dir/alice`      | NONE (no dash)          |
//! | `"alice-up"`     | `hosts_dir/alice-up`   | suffix + `check_id`       |
//!
//! The "NONE" cases let `tinc edit ../../etc/passwd` resolve to
//! `hosts_dir/../../etc/passwd`. We add two checks upstream lacks:
//! reject `/` anywhere in the input (after the `hosts/` strip), and
//! reject `..` as a path component. Neither changes valid inputs.
//!
//! ## `system()` vs Command — shell-injection FIXED
//!
//! Upstream builds `"$EDITOR" "$FILENAME"` and passes to `system()`
//! — the double-quote escaping is wrong for `"`/`$`. We match git
//! (`editor.c` in git.git): spawn `sh -c 'exec $TINC_EDITOR "$@"' --
//! "$file"`. The shell tokenizes `$TINC_EDITOR` (so `EDITOR=
//! "emacsclient -nw"` works), but `$file` is `$@` so it's NOT
//! re-expanded (filenames with `$` stay literal).
//!
//! ## The silent reload — best-effort
//!
//! Fire-and-forget. If the daemon isn't running, silently nothing
//! happens (and that's fine — the edit was the point). If the daemon
//! IS running, it reloads. `CtlSocket::connect()` → `Err` is
//! swallowed. `send(Reload)` → don't even `recv_ack`. The daemon's
//! reload runs asynchronously; we'd be gone by the time it finishes.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::ctl::{CtlRequest, CtlSocket};
use crate::names::{Paths, check_id};

use super::CmdError;

// conffiles[] — the "edit a top-level config file" shortlist

/// The files that live DIRECTLY in `confbase` (not under `hosts/`).
/// `tinc edit tinc.conf` resolves to `confbase/tinc.conf`; `tinc edit
/// alice` resolves to `confbase/hosts/alice`. This list is the
/// discriminator.
///
/// `tinc-up`/`tinc-down`: network up/down hook scripts. `subnet-up`/
/// `subnet-down`/`host-up`/`host-down`: per-event hooks. All in
/// `confbase`, not `hosts/`. The DASH in `tinc-up` is why the
/// `conffiles` check happens BEFORE the dash-split.
const CONFFILES: &[&str] = &[
    "tinc.conf",
    "tinc-up",
    "tinc-down",
    "subnet-up",
    "subnet-down",
    "host-up",
    "host-down",
];

// Path resolution — the lattice

/// The resolution lattice. Separate from `run()` so it's unit-
/// testable WITHOUT spawning an editor.
///
/// `input`: the user's shorthand. `"tinc.conf"`, `"hosts/alice"`,
/// `"alice"`, `"alice-up"`. NOT a path.
///
/// Returns `Err` for: unknown conffile-shaped input that's also
/// invalid as a host name (`"garbage-file"` — not in CONFFILES,
/// dash-split gives suffix `"file"` which isn't `up`/`down`). Or
/// for our STRICTER checks (`/`, `..`).
///
/// # Errors
/// `BadInput("Invalid configuration filename.")` — matches
/// upstream's stderr message plus our extra rejects.
pub(crate) fn resolve(paths: &Paths, input: &str) -> Result<PathBuf, CmdError> {
    let bad = || CmdError::BadInput("Invalid configuration filename.".into());

    // ─── Step 1: strip "hosts/" prefix if present
    // After strip, `"hosts/alice"` and `"alice"` are equivalent.
    // We're Unix-only; hardcode `/`.
    let (input, stripped) = match input.strip_prefix("hosts/") {
        Some(rest) => (rest, true),
        None => (input, false),
    };

    // ─── Step 2 (NOT upstream): reject path-traversal
    // `/` in the (post-strip) input means they're trying to reach
    // outside `hosts_dir`. `..` likewise. Upstream doesn't check;
    // `tinc edit ../../etc/passwd` works there. We reject.
    //
    // The `/` check subsumes most `..` cases (`../foo` has both)
    // but `..` alone (`tinc edit hosts/..`) would be `hosts_dir/..`
    // = `confbase` — harmless, but unintended. Reject both. Empty
    // string → `hosts_dir/` itself; reject.
    if input.is_empty() || input.contains('/') || input == ".." {
        return Err(bad());
    }

    // ─── Step 3: conffiles check (skipped if we stripped)
    // If the user said `"hosts/tinc.conf"` they MEANT the host file
    // named `tinc.conf`. The strip happened first; we don't
    // conffiles-check the stripped name.
    //
    // `"tinc.conf"` → conffiles match → `confbase/tinc.conf`.
    // `"hosts/tinc.conf"` → strip → SKIP conffiles →
    // `hosts_dir/tinc.conf`. Different files.
    if !stripped && let Some(&conf) = CONFFILES.iter().find(|&&f| f == input) {
        return Ok(paths.confbase.join(conf));
    }

    // ─── Step 4: it's a host file — validate the dash form
    // The path is `hosts_dir/input` UNCONDITIONALLY. The dash check
    // only VALIDATES; it doesn't change the path.
    //
    // No dash → no validation. `"alice"` is fine. `"192.168.1.1"`
    // is also fine (not a valid node name, but the no-dash case
    // isn't check_id'd). Not our problem.
    //
    // Why the dash case IS validated: `alice-up`/`alice-down` are
    // host scripts. They EXECUTE. The check_id is "is this even a
    // node?" — vi'ing `hosts/garbage-up` and having it execute
    // would be bad. (`tinc-up` never reaches here — step 3 caught
    // it.)
    //
    // First-dash split aligns with check_id's charset: `-` isn't a
    // legal name char, so `a-b-up` → `("a", "b-up")` → suffix ≠
    // `up` → error, correct since `a-b` was never a valid name.
    if let Some((name, suffix)) = input.split_once('-')
        && !((suffix == "up" || suffix == "down") && check_id(name))
    {
        return Err(bad());
    }

    // The full input (with dash, if any), NOT the split `name`.
    // The path is `hosts/alice-up`; the split was only for VALIDATION.
    Ok(paths.hosts_dir().join(input))
}

// Editor spawn — sh -c, the git way

/// Pick the editor: `$VISUAL` → `$EDITOR` → `vi`. POSIX says `vi`
/// is always there.
///
/// Returns `OsString` not `String` — env vars are bytes on Unix,
/// `EDITOR=/weird/path/émacs` is fine. `var_os` not `var`.
fn pick_editor() -> OsString {
    // EMPTY (`EDITOR=`) is "set" — `var_os` returns `Some("")`;
    // `Command::new("")` will fail. The user who sets `EDITOR=`
    // deserves the error.
    std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .unwrap_or_else(|| OsString::from("vi"))
}

/// Spawn the editor via `sh -c` for shell-tokenized `$EDITOR`
/// WITHOUT shell-expanding the filename.
///
/// The construction:
///
/// ```text
///   sh -c '"$EDITOR" "$@"' edit-sh <filename>
///        │  │         │    │       │
///        │  │         │    │       └─ becomes $1 = "$@" (one arg)
///        │  │         │    └──────── becomes $0 (script name; arbitrary)
///        │  │         └───────────── positional args, individually quoted
///        │  └─────────────────────── shell-expanded (EDITOR="vim -f" → vim -f)
///        └────────────────────────── the script
/// ```
///
/// `$TINC_EDITOR` is UNQUOTED in the script so the shell word-
/// splits it (`EDITOR="emacsclient -nw"` → two argv entries).
/// Unquoted also globs, but that's the user's own EDITOR — git
/// accepts the same risk. The construction:
///
///   `sh -c '$TINC_EDITOR "$@"' tinc-edit <file>`
///
/// with `TINC_EDITOR` set in the Command's env. Why a custom env
/// var instead of inheriting `EDITOR`: because we ALREADY resolved
/// `VISUAL`/`EDITOR`/`vi` in `pick_editor()`. Passing the result
/// via env is cleaner than re-doing the resolution in the shell
/// script (`${VISUAL:-${EDITOR:-vi}}` would work but duplicates
/// the logic).
///
/// `editor` is `OsString` — `.env()` accepts `OsStr`. The shell
/// receives bytes; `$TINC_EDITOR` expands to those bytes. UTF-8
/// or not, the shell doesn't care.
///
/// Returns the editor's exit status; nonzero = failure.
///
/// Why `tinc-edit` for `$0`: it shows up in `ps` and in the
/// shell's error messages. Better than `sh` or `--`.
///
/// # Errors
/// `Command::status()` I/O. `sh` not found (would be a VERY broken
/// system). The editor itself failing is `Ok(nonzero status)`,
/// not an Err.
fn spawn_editor(editor: &OsString, file: &PathBuf) -> std::io::Result<std::process::ExitStatus> {
    // The script. `$TINC_EDITOR` unquoted → word-split. `"$@"`
    // quoted → each positional arg stays one word. Standard sh.
    //
    // `exec` so the shell doesn't fork-and-wait — the editor IS
    // the process. One fewer pid; the wait below waits for the
    // editor directly. `exec` accepts multiple args after word-split
    // (`exec vim -f file` works), so $TINC_EDITOR with flags is fine.
    const SCRIPT: &str = r#"exec $TINC_EDITOR "$@""#;

    Command::new("sh")
        .arg("-c")
        .arg(SCRIPT)
        // `$0` for the script. Shows in error messages.
        .arg("tinc-edit")
        // `$1` = the file. `"$@"` quotes it; `$` `*` `"` etc in
        // the path stay literal.
        .arg(file)
        // The resolved editor. Inherits parent env otherwise
        // (`TERM` etc, which the editor needs).
        .env("TINC_EDITOR", editor)
        // stdin/stdout/stderr inherited — the editor IS interactive.
        // (Default for `status()`; explicit comment for clarity.)
        .status()
}

// CLI entry

/// `tinc edit FILE`.
///
/// Resolve the shorthand → spawn editor → wait → silent reload.
///
/// The `paths` for both resolve (`confbase/hosts_dir`) AND the
/// reload (pidfile/socket). `needs_daemon: false` in the binary's
/// table — the reload is OPTIONAL, the edit isn't blocked on a
/// running daemon.
///
/// `needs_daemon` in the binary controls whether `Paths` gets the
/// pidfile resolved. We set `true` so `CtlSocket::connect` has a
/// path to try, even though we might not use it. Same as `top` and
/// `log`.
///
/// # Errors
/// `BadInput("Invalid configuration filename.")` for unresolvable
/// input. `BadInput(editor exit)` for editor nonzero. `Io` for
/// `sh` spawn failing (rare).
///
/// The reload is BEST-EFFORT — never errors. Daemon down? Fine.
/// Reload failed daemon-side? Also fine. The edit happened; that's
/// success.
#[cfg(unix)]
pub fn run(paths: &Paths, input: &str) -> Result<(), CmdError> {
    // ─── Resolve
    let resolved = resolve(paths, input)?;

    // ─── Edit
    let editor = pick_editor();
    let status = spawn_editor(&editor, &resolved).map_err(|e| {
        // `sh` not found, or some exec-level failure. Not "editor
        // exited nonzero" — that's the `Ok(status)` path below.
        CmdError::Io {
            // `sh` is what we spawned. The path that failed.
            // (`PathBuf::from("sh")` is a lie — we don't know
            // WHERE sh is. But `CmdError::Io` wants a path. The
            // message will say "Could not access sh: ..." which
            // is close enough.)
            path: PathBuf::from("sh"),
            err: e,
        }
    })?;

    // Nonzero exit = failure. `status.success()` is exit-code-aware
    // (upstream returned the raw wait-status, which is a bug we
    // don't replicate). SIGINT in the editor → also false →
    // edit-aborted, no reload.
    if !status.success() {
        // `editor` is `OsString`. `to_string_lossy` for the error
        // message — non-UTF-8 EDITOR shows as replacement chars,
        // which is fine for an error message.
        return Err(CmdError::BadInput(format!(
            "Editor `{}` exited with {status}",
            editor.to_string_lossy()
        )));
    }

    // ─── Silent reload
    // Swallow connect Err (daemon being down is a normal case). NO
    // `recv_ack` — fire and forget. We also don't care about send
    // failing; the socket might be half-dead, whatever.
    if let Ok(mut ctl) = CtlSocket::connect(paths) {
        let _ = ctl.send(CtlRequest::Reload);
        // No recv. We're about to exit; the socket closes; the
        // daemon's `recvline` returns false; it cleans up.
    }

    Ok(())
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::PathsInput;

    fn paths() -> Paths {
        Paths::for_cli(&PathsInput {
            confbase: Some(PathBuf::from("/etc/tinc/test")),
            ..Default::default()
        })
    }

    // resolve — the lattice

    /// `resolve` Ok-path table. The lattice: conffiles check FIRST
    /// (returns early), then `hosts/` strip, then dash-split for
    /// validation only.
    ///
    /// The `Dir` enum lets us check the resolved path against either
    /// `confbase` or `hosts_dir` without hardcoding the test confbase.
    #[test]
    fn resolve_ok() {
        enum Dir {
            Conf,
            Hosts,
        }
        let p = paths();
        #[rustfmt::skip]
        let cases: &[(&str, Dir, &str)] = &[
            //          (input,             dir,        joined)
            // ─── conffile match → confbase/X ───
            ("tinc.conf",        Dir::Conf,  "tinc.conf"),
            // ─── bare name (no dash) → hosts_dir/X. NO validation. ───
            ("alice",            Dir::Hosts, "alice"),
            // ─── `hosts/` prefix strip ───
            ("hosts/alice",      Dir::Hosts, "alice"),
            // ─── `hosts/tinc.conf` → hosts_dir/tinc.conf, NOT confbase.
            //     THE non-obvious case. Strip happens FIRST; conffiles check
            //     runs only WITHOUT the prefix. Pins branch order. ───
            ("hosts/tinc.conf",  Dir::Hosts, "tinc.conf"),
            // ─── dash-split for validation. Path keeps the dash. ───
            ("alice-up",         Dir::Hosts, "alice-up"),
            ("alice-down",       Dir::Hosts, "alice-down"),
            // ─── `tinc-up` matches CONFFILES → confbase. NOT dash-split.
            //     Pins the order: conffiles BEFORE dash-split. Would otherwise
            //     split to ("tinc","up") — both valid → hosts_dir/tinc-up. WRONG. ───
            ("tinc-up",          Dir::Conf,  "tinc-up"),
            // ─── `"."`: weird (vi hosts_dir/.) but accepted (no dash, no slash).
            //     The `..` reject is the security one; `.` is just odd. ───
            (".",                Dir::Hosts, "."),
        ];
        for (input, dir, joined) in cases {
            let r = resolve(&p, input).unwrap();
            let expected = match dir {
                Dir::Conf => p.confbase.join(joined),
                Dir::Hosts => p.hosts_dir().join(joined),
            };
            assert_eq!(r, expected, "input: {input:?}");
        }
        // All seven conffiles resolve to confbase/X.
        for &f in CONFFILES {
            let r = resolve(&p, f).unwrap();
            assert_eq!(r, p.confbase.join(f), "conffile: {f}");
        }
    }

    /// `resolve` Err-path table. Dash-split validation + our
    /// STRICTER checks (slash/dotdot/empty — not in upstream).
    #[test]
    fn resolve_err() {
        let p = paths();
        for input in [
            // ─── dash-split validation ───
            // suffix isn't `up`/`down`.
            "alice-garbage",
            // suffix ok but `check_id("bad name")` fails (space).
            "bad name-up",
            // split at FIRST dash → name="", suffix="up". `check_id("")` fails.
            "-up",
            // split at FIRST dash → name="a", suffix="b-up". `"b-up"` ≠ `"up"`.
            // `split_once` finds FIRST dash; suffix compared WHOLE.
            "a-b-up",
            // ─── our STRICTER checks (not upstream) ───
            // slash anywhere (after `hosts/` strip). Upstream resolves
            // `hosts_dir/a/b` (path traversal); we reject.
            "a/b",
            "../etc/passwd",
            // `hosts/../etc/passwd` strips to `../etc/passwd` → has slash.
            // THE traversal case.
            "hosts/../etc/passwd",
            // `..` alone → hosts_dir/.. = confbase.
            "..",
            "hosts/..",
            // empty → hosts_dir/. Our `is_empty` catches it.
            "",
            // `hosts/` strips to "". Same rejection.
            "hosts/",
        ] {
            assert!(
                matches!(resolve(&p, input), Err(CmdError::BadInput(_))),
                "input: {input:?}"
            );
        }
    }

    // pick_editor — env precedence
    //
    // CAN'T test in-process: `set_var` is process-wide, parallel
    // tests race. (And in 2024+ Rust, `set_var` is unsafe-in-
    // edition-2024 anyway.) Tested by inspection (3 lines) +
    // integration test in `tinc_cli.rs` (subprocess with `.env()`).

    // spawn_editor — the sh -c construction
    //
    // Unit-testing `spawn_editor` would mean spawning sh. Do-able
    // but the integration test (set EDITOR=true, run `tinc edit`)
    // covers it more realistically. The construction (script
    // string, arg order, env var) is correctness-by-inspection;
    // the test is whether `EDITOR="echo arg" tinc edit alice`
    // produces "arg /path/to/hosts/alice" on stdout. Integration.
}
