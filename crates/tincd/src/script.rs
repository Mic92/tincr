//! `script.c` (253 LOC) — env-var building + `system()` caller for
//! tinc-up/tinc-down/host-up/host-down/subnet-up/subnet-down hooks.
//!
//! ## What we DON'T port
//!
//! Upstream uses `putenv()` to mutate the *process* env before
//! `system()`, then `unputenv()` to undo it. That leaks: between
//! the putenv loop and the unputenv loop, every
//! `getenv()` in the daemon sees script vars. And `unputenv()` is a
//! 35-line workaround for `putenv()` not owning its string. We use
//! [`std::process::Command::envs`] — per-spawn env, no process
//! mutation, no cleanup. The whole `unputenv` dance evaporates.
//!
//! `environment_exit` (`:137-142`) — free the `char**` arena. Drop.
//!
//! `environment_update` — overwrite a slot by index. Only caller
//! mutates `SUBNET=` and `WEIGHT=` inside a loop. The Rust call
//! site builds a fresh
//! `ScriptEnv` per iteration instead (chunk-8 wiring). Not ported.
//!
//! Windows `PATHEXT` search (`:156-199`). `#[cfg(windows)]` stubbed.
//!
//! ## Behavior differences vs C tincd
//!
//! **Shebang-less scripts fail.** Upstream `execute_script` builds a
//! quoted command string and passes it to `system()`, which is
//! `sh -c '"/etc/tinc/foo/host-up"'`. The shell reads the
//! shebang OR — if there is none — runs the file as a sh script. We
//! call [`Command::status`] which is straight `execve()`: a script
//! without `#!` fails `ENOEXEC`. We do NOT wrap in `sh -c` ourselves
//! because that reintroduces the shell-metacharacter risk for
//! `confbase` (the C is only safe because tinc.conf path validation
//! happens upstream). Workaround: set `ScriptInterpreter = /bin/sh`
//! in tinc.conf (passed here as `interpreter`), which runs
//! `<interpreter> <script>` — same effect, no shell parse of the
//! path.
//!
//! **Non-zero exit / signal don't return `false`.** Upstream returns
//! `false` on non-zero exit, signal, or `system() == -1`; callers
//! ignore the return — a failing script never aborts the daemon.
//! We return [`ScriptResult::Failed`] carrying the [`ExitStatus`]
//! so the caller can log `WEXITSTATUS`/`WTERMSIG`
//! but the type makes "failed script ≠ daemon error" explicit.

#![forbid(unsafe_code)]

use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

use crate::sandbox;

/// One script invocation's environment. Upstream `environment_t`: a
/// growing `char**` arena of `"KEY=value"` strings, fed to
/// `putenv()`. We use a `Vec` of pairs because [`Command::envs`]
/// takes
/// `IntoIterator<Item = (K, V)>`.
///
/// Keys are `&'static str` because every key in the C is a literal
/// (`"NETNAME="`, `"NODE="`, etc). Values are owned `String` because
/// they're formatted (`"%s"`, `"%d"`).
pub struct ScriptEnv {
    vars: Vec<(&'static str, String)>,
}

impl ScriptEnv {
    /// `environment_init`. Base vars every script gets. We take
    /// them as args (upstream reads from globals).
    ///
    /// `NETNAME` / `DEVICE` / `INTERFACE` are conditional in C
    /// (`:113,121,125` — `if(netname)` etc). `Option<&str>` here.
    /// `NAME` is always set by the time scripts run (set from
    /// `Name=`); required `&str` here.
    ///
    /// `DEBUG` is `if(debug_level >= 0)` (`:129`). `debug_level`
    /// is signed in C; `-1` means "don't set". We take `Option<i32>`
    /// and the caller passes `None` for that case.
    #[must_use]
    pub fn base(
        netname: Option<&str>,
        myname: &str,
        device: Option<&str>,
        iface: Option<&str>,
        debug: Option<i32>,
    ) -> Self {
        // Base count (≤5) plus typical caller adds (NODE,
        // REMOTEADDRESS, REMOTEPORT, SUBNET, WEIGHT). 10 is right.
        let mut vars = Vec::with_capacity(10);
        if let Some(n) = netname {
            vars.push(("NETNAME", n.to_owned()));
        }
        vars.push(("NAME", myname.to_owned()));
        if let Some(d) = device {
            vars.push(("DEVICE", d.to_owned()));
        }
        if let Some(i) = iface {
            vars.push(("INTERFACE", i.to_owned()));
        }
        if let Some(level) = debug {
            vars.push(("DEBUG", level.to_string()));
        }
        Self { vars }
    }

    /// `environment_add` for one var. We take key + formatted
    /// value. Call sites: NODE, REMOTEADDRESS, REMOTEPORT,
    /// SUBNET, WEIGHT.
    pub fn add(&mut self, key: &'static str, value: String) {
        self.vars.push((key, value));
    }
}

/// `execute_script` outcome. Upstream returns `bool` but callers
/// ignore it; we return an enum so the caller can log the warning
/// without conflating "no script" with "script
/// failed".
#[derive(Debug)]
pub enum ScriptResult {
    /// `access(scriptname, F_OK)` failed. The script doesn't exist.
    /// Normal — most hooks are optional. Upstream returns `true`
    /// (success) here.
    NotFound,
    /// Ran, exit 0. `if(WIFEXITED && !WEXITSTATUS)`.
    Ok,
    /// `sandbox_can(START_PROCESSES, RIGHT_NOW)` false (`
    /// 145`). Sandbox=high. C returns `false` here; callers ignore
    /// it (script never runs, daemon doesn't abort). Distinct from
    /// `NotFound` so the log says WHY — a `host-up` that silently
    /// no-ops at high should be discoverable.
    Sandboxed,
    /// Ran, exit non-zero or killed by signal (`:231-247`). C logs
    /// `LOG_ERR` and returns `false`; callers ignore the `false`.
    /// Carries [`ExitStatus`] so the daemon can format
    /// `WEXITSTATUS` / `WTERMSIG` to match the C log message.
    Failed(ExitStatus),
    /// Fire-and-forget child launched ([`spawn`]); exit status not
    /// collected here. Reaped by [`reap_children`].
    Spawned,
}

/// Shared front half of [`execute`] / [`spawn`]: gating + Command
/// build. `Err` = short-circuit result (NotFound/Sandboxed).
fn prepare(
    confbase: &Path,
    name: &str,
    env: &ScriptEnv,
    interpreter: Option<&str>,
) -> Result<Command, ScriptResult> {
    if !sandbox::can(sandbox::Action::StartProcesses) {
        return Err(ScriptResult::Sandboxed);
    }
    let scriptname = confbase.join(name);
    if !scriptname.try_exists().unwrap_or(false) {
        return Err(ScriptResult::NotFound);
    }
    log::info!("Executing script {name}");
    let mut cmd = match interpreter {
        Some(interp) => {
            let mut c = Command::new(interp);
            c.arg(&scriptname);
            c
        }
        None => Command::new(&scriptname),
    };
    cmd.env_clear();
    cmd.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    cmd.envs(env.vars.iter().map(|(k, v)| (*k, v.as_str())));
    cmd.current_dir(confbase);
    Ok(cmd)
}

/// `execute_script`.
///
/// Builds `<confbase>/<name>` (e.g. `/etc/tinc/foo/host-up`).
/// If it doesn't exist (`:201-203` `access(F_OK)`): returns
/// [`ScriptResult::NotFound`] — NOT an error. If it runs and exits
/// non-zero (`:231-238`): [`ScriptResult::Failed`] — daemon logs a
/// warning, doesn't abort.
///
/// # Errors
///
/// Spawn failures only: ENOENT-after-stat-race, EACCES, ENOEXEC
/// (shebang-less script with no `interpreter` — see module doc).
///
/// **Blocks.** Upstream uses `system()`. The daemon calls this on
/// the epoll thread; a slow tinc-up stalls the whole daemon. Same
/// in C. (Upstream wants async script spawn — out of scope.)
///
/// `interpreter` is the `ScriptInterpreter` setting (`:215-219`):
/// if `Some`, run `<interpreter> <script>`; else run `<script>`
/// directly. See module doc for the shebang caveat.
///
/// `scriptextension` (`:152`) is empty on Unix (`names.c`). Not a
/// parameter.
pub fn execute(
    confbase: &Path,
    name: &str,
    env: &ScriptEnv,
    interpreter: Option<&str>,
) -> io::Result<ScriptResult> {
    #[cfg(windows)]
    compile_error!("Windows PATHEXT search not ported");

    let mut cmd = match prepare(confbase, name, env, interpreter) {
        Ok(c) => c,
        Err(r) => return Ok(r),
    };

    // `:221` system(). status() is fork+exec+waitpid. Blocks.
    let status = cmd.status()?;

    // `:228-247`. WIFEXITED+WEXITSTATUS==0 → Ok, else Failed.
    // ExitStatus::success() is exactly that check on Unix.
    if status.success() {
        Ok(ScriptResult::Ok)
    } else {
        Ok(ScriptResult::Failed(status))
    }
}

/// Non-blocking [`execute`]: fork+exec and return immediately. The
/// child is detached; [`reap_children`] collects it later. Used for
/// per-subnet / per-host hooks that fire in bulk on the event loop.
///
/// # Errors
/// Same spawn-failure surface as [`execute`].
pub fn spawn(
    confbase: &Path,
    name: &str,
    env: &ScriptEnv,
    interpreter: Option<&str>,
) -> io::Result<ScriptResult> {
    let mut cmd = match prepare(confbase, name, env, interpreter) {
        Ok(c) => c,
        Err(r) => return Ok(r),
    };
    // Drop the Child handle: no implicit wait; pid reaped via reap_children().
    let _ = cmd.spawn()?;
    Ok(ScriptResult::Spawned)
}

/// Drain exited children spawned by [`spawn`] (and any other
/// detached forks). `waitpid(-1, WNOHANG)` until no more.
pub fn reap_children() {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Unique tempdir per test. Workspace convention: thread id in
    /// name, no `tempfile` dep. Cleanup is best-effort.
    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tincd-script-{tag}-{:?}",
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_script(dir: &Path, name: &str, body: &str) {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        let mut perm = fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&p, perm).unwrap();
    }

    #[test]
    fn not_found_is_ok() {
        // Most hooks are optional; absence is not an error.
        let dir = tmpdir("notfound");
        let env = ScriptEnv::base(None, "alpha", None, None, None);
        let r = execute(&dir, "tinc-up", &env, None).unwrap();
        assert!(matches!(r, ScriptResult::NotFound));
    }

    #[test]
    fn runs_and_succeeds() {
        let dir = tmpdir("ok");
        write_script(&dir, "tinc-up", "#!/bin/sh\nexit 0\n");
        let env = ScriptEnv::base(None, "alpha", None, None, None);
        let r = execute(&dir, "tinc-up", &env, None).unwrap();
        assert!(matches!(r, ScriptResult::Ok));
    }

    #[test]
    fn runs_and_fails() {
        // WIFEXITED && WEXITSTATUS != 0 → log + return false. We
        // carry the status for the log.
        let dir = tmpdir("fail");
        write_script(&dir, "tinc-up", "#!/bin/sh\nexit 7\n");
        let env = ScriptEnv::base(None, "alpha", None, None, None);
        match execute(&dir, "tinc-up", &env, None).unwrap() {
            ScriptResult::Failed(st) => assert_eq!(st.code(), Some(7)),
            r => panic!("expected Failed, got {r:?}"),
        }
    }

    #[test]
    fn env_vars_passed() {
        // Verify `Command::envs` actually delivers our vars to the
        // child. The `putenv` loop is the thing we're replacing;
        // this proves the replacement works.
        let dir = tmpdir("env");
        let out = dir.join("out");
        write_script(
            &dir,
            "host-up",
            &format!("#!/bin/sh\necho \"$NAME $NODE\" > '{}'\n", out.display()),
        );
        let mut env = ScriptEnv::base(None, "alpha", None, None, None);
        env.add("NODE", "beta".to_owned());
        let r = execute(&dir, "host-up", &env, None).unwrap();
        assert!(matches!(r, ScriptResult::Ok));
        let got = fs::read_to_string(&out).unwrap();
        assert_eq!(got.trim(), "alpha beta");
    }

    #[test]
    fn env_is_cleared() {
        // Child sees only the fixed PATH + tinc vars, nothing
        // inherited from the test runner (HOME etc.).
        let dir = tmpdir("envclear");
        let out = dir.join("out");
        write_script(
            &dir,
            "tinc-up",
            &format!(
                "#!/bin/sh\nprintf '%s|%s' \"$PATH\" \"${{HOME:-unset}}\" > '{}'\n",
                out.display()
            ),
        );
        let env = ScriptEnv::base(None, "alpha", None, None, None);
        let r = execute(&dir, "tinc-up", &env, None).unwrap();
        assert!(matches!(r, ScriptResult::Ok));
        assert_eq!(
            fs::read_to_string(&out).unwrap(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|unset"
        );
    }

    #[test]
    fn base_env_has_expected_keys() {
        // The conditional adds. NETNAME only if
        // netname global is set; same for DEVICE, INTERFACE. NAME
        // and DEBUG always (in practice).
        let env = ScriptEnv::base(
            Some("vpn"),
            "alpha",
            Some("/dev/net/tun"),
            Some("tun0"),
            Some(2),
        );
        let keys: Vec<_> = env.vars.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, ["NETNAME", "NAME", "DEVICE", "INTERFACE", "DEBUG"]);
        assert_eq!(env.vars[4].1, "2");

        // None branches: only NAME survives.
        let env = ScriptEnv::base(None, "alpha", None, None, None);
        let keys: Vec<_> = env.vars.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, ["NAME"]);
    }

    #[test]
    fn interpreter_used() {
        // Pin the behavior-change doc: shebang-less script + no
        // interpreter → ENOEXEC. Same script + `/bin/sh` → works.
        // `system()` would run both (sh -c falls back to sh-script
        // mode); we don't.
        let dir = tmpdir("interp");
        // No shebang. Valid sh, invalid execve target.
        write_script(&dir, "tinc-up", "exit 0\n");
        let env = ScriptEnv::base(None, "alpha", None, None, None);

        // Without interpreter: Linux execve() rejects shebang-less
        // file with ENOEXEC — proves we don't wrap in `sh -c`.
        // macOS kernel does its own /bin/sh fallback, so the assert
        // can't distinguish our behavior there; skip it.
        #[cfg(target_os = "linux")]
        assert!(execute(&dir, "tinc-up", &env, None).is_err());

        // With interpreter: works.
        let r = execute(&dir, "tinc-up", &env, Some("/bin/sh")).unwrap();
        assert!(matches!(r, ScriptResult::Ok));
    }

    #[test]
    fn script_cwd_is_confbase() {
        // main() chdirs to confbase; scripts inherit. A `tinc-up`
        // doing `cat hosts/$NODE` (relative) only works
        // because of that. We set `.current_dir(confbase)` on the
        // Command — this proves the script sees it.
        let dir = tmpdir("cwd");
        let probe = dir.join("cwd-probe");
        write_script(
            &dir,
            "tinc-up",
            &format!("#!/bin/sh\npwd > '{}'\n", probe.display()),
        );
        let env = ScriptEnv::base(None, "alpha", None, None, None);

        let r = execute(&dir, "tinc-up", &env, None).unwrap();
        assert!(matches!(r, ScriptResult::Ok));

        let got = fs::read_to_string(&probe).unwrap();
        // canonicalize both — tmpdir may be a symlink (/tmp →
        // /private/tmp on macOS).
        let want = dir.canonicalize().unwrap();
        let got = std::path::Path::new(got.trim()).canonicalize().unwrap();
        assert_eq!(got, want);
    }
}
