//! `tinc edit FILE` — spawn `$VISUAL`/`$EDITOR`/`vi` on a config
//! file, then silently signal the daemon to reload.
//!
//! ## Path resolution
//!
//! The input is a shorthand, not a path — the point is
//! `tinc edit tinc.conf` instead of `vi /etc/tinc/foo/tinc.conf`.
//!
//! | input            | resolves to            | validation              |
//! |------------------|------------------------|-------------------------|
//! | `"tinc.conf"`    | `confbase/tinc.conf`   | CONFFILES membership    |
//! | `"hosts/alice"`  | `hosts_dir/alice`      | none (after strip)      |
//! | `"alice"`        | `hosts_dir/alice`      | none (no dash)          |
//! | `"alice-up"`     | `hosts_dir/alice-up`   | suffix + `check_id`     |
//!
//! To prevent path traversal, `/` anywhere in the input (after the
//! `hosts/` strip) and a bare `..` are rejected.
//!
//! ## Editor spawn
//!
//! Same construction as git's editor.c: `sh -c 'exec $TINC_EDITOR "$@"' --
//! "$file"`. The shell tokenizes `$TINC_EDITOR` (so `EDITOR="emacsclient
//! -nw"` works), but the filename goes through `"$@"` and is never
//! re-expanded, so `$` in paths stays literal.
//!
//! ## Silent reload
//!
//! Fire-and-forget. If the daemon isn't running, nothing happens — the
//! edit was the point. Connect errors are swallowed and no ack is read;
//! the daemon's reload runs asynchronously anyway.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::ctl::{CtlRequest, CtlSocket};
use crate::names::{Paths, check_id};

use super::CmdError;

/// Files that live directly in `confbase` (not under `hosts/`): tinc.conf
/// plus the network/subnet/host hook scripts. The dash in `tinc-up` is why
/// this check must run before the dash-split validation.
const CONFFILES: &[&str] = &[
    "tinc.conf",
    "tinc-up",
    "tinc-down",
    "subnet-up",
    "subnet-down",
    "host-up",
    "host-down",
];

/// Resolve the user's shorthand (`"tinc.conf"`, `"hosts/alice"`, `"alice"`,
/// `"alice-up"`) to a path. Separate from `run()` so it's unit-testable
/// without spawning an editor.
///
/// # Errors
/// `BadInput("Invalid configuration filename.")` for inputs that fail the
/// dash-split validation or the traversal checks (`/`, `..`, empty).
pub(crate) fn resolve(paths: &Paths, input: &str) -> Result<PathBuf, CmdError> {
    let bad = || CmdError::BadInput("Invalid configuration filename.".into());

    // Strip "hosts/" prefix; afterwards "hosts/alice" and "alice" are
    // equivalent. Unix-only, so `/` is hardcoded.
    let (input, stripped) = match input.strip_prefix("hosts/") {
        Some(rest) => (rest, true),
        None => (input, false),
    };

    // Reject path traversal: `/` in the post-strip input reaches outside
    // hosts_dir; a bare `..` would resolve to confbase; empty input would
    // be hosts_dir itself.
    if input.is_empty() || input.contains('/') || input == ".." {
        return Err(bad());
    }

    // CONFFILES check is skipped when the "hosts/" prefix was stripped:
    // "hosts/tinc.conf" means the host file named tinc.conf, not the
    // top-level config.
    if !stripped && let Some(&conf) = CONFFILES.iter().find(|&&f| f == input) {
        return Ok(paths.confbase.join(conf));
    }

    // Host file: the path is hosts_dir/input; the dash check only validates.
    // Names with a dash must be `<node>-up`/`<node>-down` host scripts —
    // these get executed by the daemon, so `check_id` guards against
    // creating a script for a non-node. Splitting at the first dash is
    // safe because `-` is not a legal name character.
    if let Some((name, suffix)) = input.split_once('-')
        && !((suffix == "up" || suffix == "down") && check_id(name))
    {
        return Err(bad());
    }

    // Join the full input (with dash); the split was only for validation.
    Ok(paths.hosts_dir().join(input))
}

/// Pick the editor: `$VISUAL` → `$EDITOR` → `vi` (POSIX guarantees vi).
/// `OsString` because env vars are arbitrary bytes on Unix.
fn pick_editor() -> OsString {
    // An empty `EDITOR=` counts as set and later fails to spawn; that
    // error is the user's to fix.
    std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .unwrap_or_else(|| OsString::from("vi"))
}

/// Spawn the editor via `sh -c` so `$EDITOR` is shell-tokenized
/// (`EDITOR="emacsclient -nw"` works) while the filename passes through
/// `"$@"` and is never re-expanded.
///
/// The resolved editor is passed via a private `TINC_EDITOR` env var
/// because the VISUAL/EDITOR/vi fallback already happened in
/// [`pick_editor`]; re-doing it in the shell would duplicate the logic.
/// `$0` is set to `tinc-edit` so it shows up usefully in ps and shell
/// error messages.
///
/// Returns the editor's exit status. The editor exiting nonzero is
/// `Ok(nonzero)`, not an `Err`.
///
/// # Errors
/// I/O errors from spawning `sh` itself.
fn spawn_editor(editor: &OsString, file: &PathBuf) -> std::io::Result<std::process::ExitStatus> {
    // `$TINC_EDITOR` unquoted → word-split (flags allowed); `"$@"` quoted →
    // filename stays one word. `exec` so the editor replaces the shell and
    // we wait on it directly.
    const SCRIPT: &str = r#"exec $TINC_EDITOR "$@""#;

    Command::new("sh")
        .arg("-c")
        .arg(SCRIPT)
        // `$0` for the script; shows in error messages.
        .arg("tinc-edit")
        // `$1` = the file; `"$@"` keeps `$`, `*`, `"` in the path literal.
        .arg(file)
        // Parent env is otherwise inherited (TERM etc.), and stdio stays
        // attached to the terminal for the interactive editor.
        .env("TINC_EDITOR", editor)
        .status()
}

/// `tinc edit FILE`: resolve the shorthand, spawn the editor, wait,
/// then attempt a best-effort daemon reload (never an error — the edit
/// itself is the success criterion).
///
/// # Errors
/// `BadInput` for unresolvable input or a nonzero editor exit; `Io` if
/// spawning `sh` fails.
#[cfg(unix)]
pub fn run(paths: &Paths, input: &str) -> Result<(), CmdError> {
    let resolved = resolve(paths, input)?;

    let editor = pick_editor();
    let status = spawn_editor(&editor, &resolved).map_err(|e| {
        // Exec-level failure (sh not found), not "editor exited nonzero".
        // CmdError::Io wants a path; "sh" is close enough for the message.
        CmdError::Io {
            path: PathBuf::from("sh"),
            err: e,
        }
    })?;

    // Nonzero exit or death by signal aborts — no reload.
    if !status.success() {
        return Err(CmdError::BadInput(format!(
            "Editor `{}` exited with {status}",
            editor.to_string_lossy()
        )));
    }

    // Silent reload: daemon being down is normal, so connect/send errors
    // are swallowed and no ack is read.
    if let Ok(mut ctl) = CtlSocket::connect(paths) {
        let _ = ctl.send(CtlRequest::Reload);
    }

    Ok(())
}

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

    /// `resolve` Ok-path table: CONFFILES check first (early return), then
    /// `hosts/` strip, then dash-split for validation only.
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
            // conffile match → confbase/X
            ("tinc.conf",        Dir::Conf,  "tinc.conf"),
            // bare name (no dash) → hosts_dir/X, no validation
            ("alice",            Dir::Hosts, "alice"),
            // `hosts/` prefix strip
            ("hosts/alice",      Dir::Hosts, "alice"),
            // hosts/tinc.conf → hosts_dir/tinc.conf, NOT confbase: strip
            // happens first, so the CONFFILES check is skipped. Pins branch order.
            ("hosts/tinc.conf",  Dir::Hosts, "tinc.conf"),
            // dash-split is validation only; path keeps the dash
            ("alice-up",         Dir::Hosts, "alice-up"),
            ("alice-down",       Dir::Hosts, "alice-down"),
            // tinc-up matches CONFFILES → confbase; pins that the CONFFILES
            // check runs before the dash-split (which would send it to hosts_dir).
            ("tinc-up",          Dir::Conf,  "tinc-up"),
            // "." is odd (vi hosts_dir/.) but accepted: no dash, no slash.
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

    /// `resolve` Err-path table: dash-split validation plus the
    /// traversal checks (slash/dotdot/empty).
    #[test]
    fn resolve_err() {
        let p = paths();
        for input in [
            // dash-split validation
            // suffix isn't up/down
            "alice-garbage",
            // suffix ok but check_id("bad name") fails (space)
            "bad name-up",
            // split at first dash → name="", check_id fails
            "-up",
            // split at first dash → suffix "b-up" ≠ "up"
            "a-b-up",
            // traversal checks
            // slash anywhere (after hosts/ strip) is rejected
            "a/b",
            "../etc/passwd",
            // strips to ../etc/passwd → still has slash
            "hosts/../etc/passwd",
            // bare .. → would be hosts_dir/.. = confbase
            "..",
            "hosts/..",
            // empty → hosts_dir itself
            "",
            // hosts/ strips to ""
            "hosts/",
        ] {
            assert!(
                matches!(resolve(&p, input), Err(CmdError::BadInput(_))),
                "input: {input:?}"
            );
        }
    }

    // pick_editor and spawn_editor are covered by the integration tests
    // (subprocess with .env()); env-var precedence can't be tested
    // in-process because set_var races across parallel tests.
}
