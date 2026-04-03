//! `tinc edit FILE` — spawn `$VISUAL`/`$EDITOR`/`vi` on a config
//! file, then silently signal the daemon to reload.
//!
//! C: `tincctl.c:2399-2472`.
//!
//! ## The path-resolution lattice (`tincctl.c:2418-2440`)
//!
//! `cmd_edit`'s input is a SHORTHAND, not a path — the point is
//! `tinc edit tinc.conf` instead of `vi /etc/tinc/foo/tinc.conf`.
//!
//! ```text
//!   conffiles[] = {"tinc.conf", "tinc-up", ..., NULL};
//!
//!   if (input doesn't start with "hosts/"):     ← :2418 strncmp
//!     for f in conffiles:                       ← :2419-2424
//!       if input == f: filename = confbase/f
//!   else:                                       ← :2425-2427
//!     input += 6                                  (strip "hosts/")
//!
//!   if filename still empty:                    ← :2429 *filename
//!     filename = hosts_dir/input                ← :2430
//!     if input contains '-':                    ← :2431-2440
//!       split at first '-'
//!       require suffix ∈ {"up","down"}
//!         AND check_id(prefix)
//! ```
//!
//! Four cases:
//!
//! | input            | resolves to            | validation              |
//! |------------------|------------------------|-------------------------|
//! | `"tinc.conf"`    | `confbase/tinc.conf`   | conffiles[] membership  |
//! | `"hosts/alice"`  | `hosts_dir/alice`      | NONE (after strip)      |
//! | `"alice"`        | `hosts_dir/alice`      | NONE (no dash)          |
//! | `"alice-up"`     | `hosts_dir/alice-up`   | suffix + check_id       |
//!
//! The "NONE" cases let `tinc edit ../../etc/passwd` resolve to
//! `hosts_dir/../../etc/passwd`. We add two checks the C lacks:
//! reject `/` anywhere in the input (after the `hosts/` strip), and
//! reject `..` as a path component. Neither changes valid inputs.
//!
//! ## system() vs Command — shell-injection FIXED
//!
//! C `tincctl.c:2455` builds `"$EDITOR" "$FILENAME"` and passes it
//! to `system()` — the double-quote escaping is wrong for `"`/`$`
//! in either expansion. We match git (`editor.c` in git.git): spawn
//! `sh -c 'exec $TINC_EDITOR "$@"' -- "$file"`. The shell tokenizes
//! `$TINC_EDITOR` (so `EDITOR="emacsclient -nw"` works), but `$file`
//! is `$@` so it's NOT re-expanded (filenames with `$` stay literal).
//!
//! ## The silent reload — best-effort
//!
//! `tincctl.c:2465-2467`:
//!
//! ```text
//!   if(connect_tincd(false)) {        ← false = don't print error
//!     sendline(fd, "%d %d", CONTROL, REQ_RELOAD);
//!   }
//! ```
//!
//! No `recvline`. No status check. Fire-and-forget. If the daemon
//! isn't running, silently nothing happens (and that's fine — the
//! edit was the point). If the daemon IS running, it reloads.
//!
//! We do the same. `CtlSocket::connect()` → `Err` is swallowed.
//! `send(Reload)` → don't even `recv_ack`. The daemon's `reload_
//! configuration` runs asynchronously; we'd be gone by the time
//! it finishes anyway.

#![allow(clippy::doc_markdown)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::ctl::{CtlRequest, CtlSocket};
use crate::names::{Paths, check_id};

use super::CmdError;

// conffiles[] — the "edit a top-level config file" shortlist

/// `tincctl.c:2399-2408`. The files that live DIRECTLY in `confbase`
/// (not under `hosts/`). `tinc edit tinc.conf` resolves to `confbase/
/// tinc.conf`; `tinc edit alice` resolves to `confbase/hosts/alice`.
/// This list is the discriminator.
///
/// Order preserved from C (sed-verifiable). Doesn't matter for
/// correctness (we check membership, not first-match) but matching
/// the C makes the diff trivially auditable.
///
/// `tinc-up`/`tinc-down`: the network up/down hook scripts. `subnet-
/// up`/`subnet-down`/`host-up`/`host-down`: per-event hooks. All in
/// `confbase`, not `hosts/`. The DASH in `tinc-up` is why the
/// `conffiles` check happens BEFORE the dash-split (`tincctl.c:2418`
/// checks list FIRST; only if not found does it dash-split).
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

/// What `cmd_edit` resolved an input to. The PATH plus whether
/// we should mkdir-p the parent (host files: yes, the `hosts/` dir
/// might not exist for a fresh `tinc init`; conffiles: confbase
/// already exists).
///
/// Not in the C — `cmd_edit` does mkdir-p never. `tinc edit alice`
/// on a fresh tree fails when vi can't write to a nonexistent
/// `hosts/`. The "create hosts/ if missing" is our addition; one
/// `create_dir_all` doesn't hurt and `tinc init` does it anyway.
///
/// Actually NOT adding it — port C behavior. The `hosts/` mkdir
/// is `tinc init`'s job. If `hosts/` doesn't exist, the user
/// hasn't run `init`, and the editor will tell them when save
/// fails. Consistent with C; one less thing to test.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    /// Full path. The caller spawns `$EDITOR` on this.
    pub(crate) path: PathBuf,
}

/// `tincctl.c:2418-2440` — the resolution lattice. Separate from
/// `run()` so it's unit-testable WITHOUT spawning an editor.
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
/// `BadInput("Invalid configuration filename.")` — matches the C's
/// stderr message (`tincctl.c:2438`) plus our extra rejects.
pub(crate) fn resolve(paths: &Paths, input: &str) -> Result<Resolved, CmdError> {
    let bad = || CmdError::BadInput("Invalid configuration filename.".into());

    // ─── Step 1: strip "hosts/" prefix if present
    // `tincctl.c:2418`: `if(strncmp(argv[1], "hosts" SLASH, 6))`.
    // The `strncmp != 0` means "DOESN'T start with" — so the
    // conffiles check runs when there's NO prefix, and the strip
    // runs when there IS. Somewhat backwards-reading C.
    //
    // After strip, `"hosts/alice"` and `"alice"` are equivalent.
    // The C does this by `argv[1] += 6` (mutate the input pointer);
    // we do it by re-binding `input`.
    //
    // `"hosts/"` literal (6 chars). The C uses `SLASH` macro for
    // Windows backslash; we're Unix-only, hardcode `/`.
    let (input, stripped) = match input.strip_prefix("hosts/") {
        Some(rest) => (rest, true),
        None => (input, false),
    };

    // ─── Step 2 (NOT in C): reject path-traversal
    // `/` in the (post-strip) input means they're trying to reach
    // outside `hosts_dir`. `..` likewise. The C doesn't check;
    // `tinc edit ../../etc/passwd` works there. We reject.
    //
    // The `/` check subsumes most `..` cases (`../foo` has both)
    // but `..` alone (`tinc edit hosts/..`) would be `hosts_dir/..`
    // = `confbase` — harmless, but the user clearly didn't mean
    // it. Reject both.
    //
    // Empty string: `tinc edit ""` → would be `hosts_dir/` (the dir
    // itself). Reject. The C doesn't check; vi-on-a-directory
    // works but is confusing. Our `is_empty` catches it.
    if input.is_empty() || input.contains('/') || input == ".." {
        return Err(bad());
    }

    // ─── Step 3: conffiles check (skipped if we stripped)
    // `tincctl.c:2419-2424`: only inside the `!strncmp` branch.
    // If the user said `"hosts/tinc.conf"` they MEANT the host
    // file named `tinc.conf` (weird but valid: a node named
    // `tinc.conf` would need a host config file). The strip
    // happened first; we don't conffiles-check the stripped name.
    //
    // `"tinc.conf"` (no prefix) → conffiles match → `confbase/
    // tinc.conf`. `"hosts/tinc.conf"` (prefix) → strip →
    // `"tinc.conf"` → SKIP conffiles check → `hosts_dir/
    // tinc.conf`. Different files. The C does this by the branch
    // structure (conffiles loop is inside the `!prefix` arm).
    if !stripped {
        if let Some(&conf) = CONFFILES.iter().find(|&&f| f == input) {
            // `tincctl.c:2422`: `confbase SLASH argv[1]`.
            return Ok(Resolved {
                path: paths.confbase.join(conf),
            });
        }
    }

    // ─── Step 4: it's a host file — validate the dash form
    // `tincctl.c:2429-2440`. The path is `hosts_dir/input`
    // UNCONDITIONALLY (the snprintf at :2430 happens before the
    // dash check). The dash check only VALIDATES; it doesn't
    // change the path.
    //
    // `strchr(argv[1], '-')`: first dash. If found, split there.
    // `dash++` after `*dash = 0`: classic C "split string in
    // place, advance past the separator." The PREFIX is `argv[1]`
    // (now NUL-terminated at the dash); the SUFFIX is `dash`.
    //
    // The check (`tincctl.c:2437`): suffix is "up" or "down" AND
    // prefix is a valid node name. Otherwise error.
    //
    // No dash → no validation. `"alice"` is fine. `"192.168.1.1"`
    // is also fine (not a valid node name, but the C doesn't
    // check_id the no-dash case). The user gets vi on `hosts_dir/
    // 192.168.1.1`; if they save it the daemon will choke later.
    // Not our problem (and STRICTER would break valid names that
    // happen to look weird).
    //
    // Why the dash case IS validated: `alice-up`/`alice-down` are
    // host scripts (`tinc-up` analogues but per-host). They
    // EXECUTE. The check_id is "is this even a node?" — vi'ing
    // `hosts/garbage-up` and having it execute would be bad.
    //
    // ACTUALLY: the C ALSO validates `"tinc-up"` here? No —
    // `tinc-up` matched conffiles[] in step 3, returned early.
    // Step 4 only sees inputs that didn't match conffiles. So
    // `"X-up"` here means X is a HOST name, not `"tinc"`. Good.
    //
    // The first dash, not the last: `find('-')`. A node named
    // `"a-b"` (legal! check_id allows `_` but NOT `-`, so actually
    // no: `tincctl.c:108`: `isalnum || c == '_'`). Dash isn't a
    // legal name char. So `"a-b-up"` splits to `("a", "b-up")`,
    // suffix is `"b-up"` ≠ `"up"`, error. Correct: `a-b` isn't a
    // valid name anyway. The first-dash split happens to align
    // with check_id's charset.
    if let Some((name, suffix)) = input.split_once('-') {
        // `tincctl.c:2437`: `(strcmp(dash, "up") && strcmp(dash,
        // "down"))` — both nonzero means neither matches. C boolean
        // logic via strcmp. The OR with `!check_id` is the second
        // check. De Morgan: `!(suffix∈{up,down} && check_id)`.
        if !((suffix == "up" || suffix == "down") && check_id(name)) {
            return Err(bad());
        }
    }
    // No dash → `if let` doesn't enter → no validation. Matches
    // the C `if(dash)` skip.

    // `tincctl.c:2430`: `hosts_dir SLASH argv[1]`. The full input
    // (with dash, if any), NOT the split `name`. The path is
    // `hosts/alice-up`; the split was only for VALIDATION.
    Ok(Resolved {
        path: paths.hosts_dir().join(input),
    })
}

// Editor spawn — sh -c, the git way

/// Pick the editor. `tincctl.c:2444-2453` (Unix branch):
///
/// ```text
///   const char *editor = getenv("VISUAL");
///   if(!editor) editor = getenv("EDITOR");
///   if(!editor) editor = "vi";
/// ```
///
/// `VISUAL` first (the convention: `VISUAL` for full-screen editors,
/// `EDITOR` for line editors; in 2026 they're synonymous). `vi` as
/// last resort (POSIX says it's always there).
///
/// Returns `OsString` not `String` — env vars are bytes on Unix,
/// `EDITOR=/weird/path/émacs` is fine. `var_os` not `var`.
fn pick_editor() -> OsString {
    // The C `getenv` returns NULL for unset; `var_os` returns None.
    // EMPTY (`EDITOR=`) is "set" — `getenv` returns `""`, the C
    // would `xasprintf("\"\" \"%s\"", ...)` and `system` would try
    // to run `""`. Broken. Our `var_os` returns `Some("")`;
    // `Command::new("")` will fail too. Same brokenness, ported.
    //
    // (Could check empty-and-fall-through, but that's a behavior
    // change. The user who sets `EDITOR=` deserves the error.)
    std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .unwrap_or_else(|| OsString::from("vi"))
}

/// Spawn the editor. `tincctl.c:2455-2458`, but via `sh -c` for
/// shell-tokenized `$EDITOR` WITHOUT shell-expanding the filename.
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
/// `"$EDITOR"` IN the script: the shell reads the env var and
/// word-splits it. `EDITOR="emacsclient -nw"` becomes two argv
/// entries to execvp.
///
/// Wait. Double-quoted `"$EDITOR"` is NOT word-split. That's the
/// POINT of double-quoting in shell. `$EDITOR` (unquoted) is
/// word-split. So the script should be `$EDITOR "$@"` —
/// editor unquoted (split it), filename quoted (don't split it).
///
/// But unquoted `$EDITOR` ALSO does glob expansion. `EDITOR='vim
/// foo*'` would glob `foo*`. Unlikely but wrong. The git way
/// (`editor.c:63` in git.git) is: just `system()`-style with the
/// filename appended via `$@`. Git's actual line: `sh -c
/// '$GIT_EDITOR "$@"' "$GIT_EDITOR" filename...`. The unquoted
/// `$GIT_EDITOR` gets split (and globbed, but git accepts that).
///
/// We accept the glob risk (it's the user's own EDITOR; they're
/// only hurting themselves). The construction:
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
/// Returns the editor's exit status. `tincctl.c:2461`: `if(result)`
/// — nonzero = failure. The caller maps to error.
///
/// Why `tinc-edit` for `$0`: it shows up in `ps` and in the
/// shell's error messages (`tinc-edit: line 1: foo: command not
/// found`). Better than `sh` or `--`.
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
        // `$0` for the script. Shows in error messages. The C
        // `system()` would show `sh` here; ours is more useful.
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

/// `tinc edit FILE`. `tincctl.c:2410-2472`.
///
/// Resolve the shorthand → spawn editor → wait → silent reload.
///
/// The `paths` for both resolve (confbase/hosts_dir) AND the
/// reload (pidfile/socket). `needs_daemon: false` in the binary's
/// table — the reload is OPTIONAL, the edit isn't blocked on a
/// running daemon.
///
/// Actually `needs_daemon` in the binary controls whether `Paths`
/// gets the pidfile resolved. If `false`, `paths.pidfile()` might
/// not be set, and `CtlSocket::connect` would fail on a missing
/// pidfile. The C `tincctl.c:3034`: `{"edit", cmd_edit, false}`.
/// `false` means "doesn't need a connection BEFORE running" — but
/// `cmd_edit` still calls `connect_tincd(false)` AFTER. Our
/// `needs_daemon: true` is the lie that makes `Paths` resolve the
/// pidfile path, even though we might not use it. Same as `top`
/// and `log`. Set `true` in the binary.
///
/// # Errors
/// `BadInput("Invalid configuration filename.")` for unresolvable
/// input. `BadInput(editor exit)` for editor nonzero. `Io` for
/// `sh` spawn failing (rare).
///
/// The reload is BEST-EFFORT — never errors. Daemon down? Fine.
/// Reload failed daemon-side? Also fine (the C doesn't even
/// `recvline` the ack). The edit happened; that's success.
#[cfg(unix)]
pub fn run(paths: &Paths, input: &str) -> Result<(), CmdError> {
    // ─── Resolve
    let resolved = resolve(paths, input)?;

    // ─── Edit
    let editor = pick_editor();
    let status = spawn_editor(&editor, &resolved.path).map_err(|e| {
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

    // `tincctl.c:2461`: `if(result) return result`. Nonzero exit
    // = failure. The C returns the raw `system()` result (which is
    // the wait-status, NOT the exit code — `WEXITSTATUS` would be
    // needed; the C doesn't do that, so `tinc edit` returning 256
    // for editor-exit-1 is a C bug). We use `status.success()`,
    // which IS exit-code-aware. Our error message includes the
    // status; the C just propagates the int.
    //
    // SIGINT in the editor: `status.success()` is false (signal
    // termination). The C's `result` is also nonzero (`system()`
    // returns the wait-status, signal-terminated is nonzero).
    // Same: edit-aborted, no reload.
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
    // `tincctl.c:2465-2467`: `if(connect_tincd(false)) sendline(
    // ..., REQ_RELOAD)`. The `false` is "don't fprintf stderr on
    // connect failure." We swallow the Err. NO `recv_ack` — the C
    // doesn't `recvline` either. Fire and forget.
    //
    // `if let Ok` not `match` — we don't CARE about Err. The
    // daemon being down is a normal case (you edit, then start).
    //
    // `_ = ctl.send(...)` — we ALSO don't care about send failing.
    // The C doesn't check `sendline`'s return either (`:2466`
    // bare call). The socket might be half-dead; whatever.
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

    // CONFFILES — sed-verified vs C

    /// `tincctl.c:2399-2408`. sed-verifiable:
    ///   sed -n '2400,2406p' src/tincctl.c | sed 's/.*"\(.*\)".*/\1/'
    /// produces these seven strings in order.
    #[test]
    fn conffiles_match_c() {
        assert_eq!(
            CONFFILES,
            &[
                "tinc.conf",
                "tinc-up",
                "tinc-down",
                "subnet-up",
                "subnet-down",
                "host-up",
                "host-down",
            ]
        );
    }

    // resolve — the lattice

    /// `resolve` Ok-path table. The lattice is `tincctl.c:2419-2440`:
    /// conffiles check FIRST (`:2419`, returns early), then `hosts/`
    /// strip (`:2425`), then dash-split for validation only (`:2431`).
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
            // ─── conffile match → confbase/X. `tincctl.c:2422`. ───
            ("tinc.conf",        Dir::Conf,  "tinc.conf"),
            // ─── bare name (no dash) → hosts_dir/X. NO validation.
            //     `tincctl.c:2430` without entering `if(dash)` (`:2433`). ───
            ("alice",            Dir::Hosts, "alice"),
            // ─── `hosts/` prefix strip. `tincctl.c:2426`: `argv[1] += 6`. ───
            ("hosts/alice",      Dir::Hosts, "alice"),
            // ─── `hosts/tinc.conf` → hosts_dir/tinc.conf, NOT confbase.
            //     THE non-obvious case. Strip happens FIRST (`:2425`);
            //     conffiles check runs only WITHOUT the prefix. Pins branch order. ───
            ("hosts/tinc.conf",  Dir::Hosts, "tinc.conf"),
            // ─── dash-split for validation. `tincctl.c:2431-2440`.
            //     Path keeps the dash; split is validation-only. ───
            ("alice-up",         Dir::Hosts, "alice-up"),
            ("alice-down",       Dir::Hosts, "alice-down"),
            // ─── `tinc-up` matches CONFFILES → confbase. NOT dash-split.
            //     Pins the order: conffiles BEFORE dash-split. Would otherwise
            //     split to ("tinc","up") — both valid → hosts_dir/tinc-up. WRONG. ───
            ("tinc-up",          Dir::Conf,  "tinc-up"),
            // ─── `"."`: weird (vi hosts_dir/.) but C accepts (no dash, no slash).
            //     NOT in our reject list. The `..` reject is the security one;
            //     `.` is just odd. Port C behavior. ───
            (".",                Dir::Hosts, "."),
        ];
        for (input, dir, joined) in cases {
            let r = resolve(&p, input).unwrap();
            let expected = match dir {
                Dir::Conf => p.confbase.join(joined),
                Dir::Hosts => p.hosts_dir().join(joined),
            };
            assert_eq!(r.path, expected, "input: {input:?}");
        }
        // All seven conffiles resolve to confbase/X.
        for &f in CONFFILES {
            let r = resolve(&p, f).unwrap();
            assert_eq!(r.path, p.confbase.join(f), "conffile: {f}");
        }
    }

    /// `resolve` Err-path table. C `tincctl.c:2437` validation +
    /// our STRICTER checks (slash/dotdot/empty rejection — not in C).
    #[test]
    fn resolve_err() {
        let p = paths();
        for input in [
            // ─── dash-split validation: `tincctl.c:2437` ───
            // suffix isn't `up`/`down`. `strcmp(dash, "up") && strcmp(dash, "down")`.
            "alice-garbage",
            // suffix ok but `check_id("bad name")` fails (space). `|| !check_id(argv[1])`.
            "bad name-up",
            // split at FIRST dash → name="", suffix="up". `check_id("")` fails.
            // C: `argv[1]` becomes "" after `*dash = 0`.
            "-up",
            // split at FIRST dash → name="a", suffix="b-up". `"b-up"` ≠ `"up"`.
            // C `strchr` finds FIRST dash; `strcmp(dash, "up")` compares WHOLE
            // suffix including subsequent dashes. Same as `split_once`.
            "a-b-up",
            // ─── our STRICTER checks (not in C) ───
            // slash anywhere (after `hosts/` strip). C would resolve
            // `hosts_dir/a/b` (path traversal); we reject.
            "a/b",
            "../etc/passwd",
            // `hosts/../etc/passwd` strips to `../etc/passwd` → has slash.
            // THE traversal case. C would `vi confbase/hosts/../etc/passwd`.
            "hosts/../etc/passwd",
            // `..` alone → hosts_dir/.. = confbase. C would `vi confbase` (a dir).
            "..",
            "hosts/..",
            // empty → C would `vi hosts_dir/`. Our `is_empty` catches it.
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
