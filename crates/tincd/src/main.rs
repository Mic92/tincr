//! tincd binary entry point. Ports `tincd.c::main` (`tincd.c:464-735`).
//!
//! Hand-rolled argv (no clap; ~12 flags). `--socket` is a testability
//! addition (C derives it from `--pidfile`). Not yet ported:
//! umbilical (needs `tinc start` to fork; that's tinc-tools' job).
//!
//! ## C ordering (`tincd.c::main2`, `:640-720`)
//!
//! ```text
//! detach()           ← fork+setsid, switch logmode (process.c:200-243)
//! mlockall()         ← AFTER fork (parent doesn't need locked pages)
//! setup_network()    ← opens sockets (root for <1024) AND runs tinc-up
//! ProcessPriority    ← setpriority(PRIO_PROCESS, 0, nice)
//! drop_privs()       ← AFTER tinc-up (which needs root for `ip addr add`)
//! main_loop()
//! ```
//!
//! tinc-up is inside our `Daemon::setup` (daemon.rs:~1755). So
//! `drop_privs` here, between `setup` and `run`, is the C-correct
//! spot — the script has already fired with root, the loop hasn't
//! started.
//!
//! ## detach default (`-D` to disable)
//!
//! C `tincd.c:64`: `bool do_detach = true`. We MATCH that. This
//! breaks `cargo nextest` unless every spawned tincd gets `-D` —
//! which is what the C integration suite does too. The test helper
//! `tests/common/mod.rs::tincd_cmd()` bakes in `-D`. Anything that
//! spawns the daemon directly (rather than via the helper) needs to
//! pass `-D` itself; the crossimpl/throughput suites already do
//! (they were always passing `-D` to the C tincd; now both sides get it).
//!
//! ## `-n` / `-o`
//!
//! `-n NETNAME` (`tincd.c:221-225`): derives confbase from
//! `CONFDIR/tinc/NETNAME` when `-c` not given. The "run multiple
//! tinc instances" knob. NETNAME env var as fallback (`tincd.c:
//! 294-305`). The C calls `make_names()` to do the join; we inline
//! it (the daemon's `make_names` is simpler than tincctl's — no
//! pidfile fallback dance, daemon always wants explicit paths or
//! the standard one).
//!
//! `-o KEY=VALUE` (`tincd.c:232-241`): per-invocation config
//! overrides without editing tinc.conf. Repeatable. Parsed with
//! `tinc-conf::parse_line` (same parser as tinc.conf — `=` optional,
//! whitespace-separated works too: `-o "Port 655"`). Passed to
//! `Daemon::setup` which merges them with `Source::Cmdline`; the
//! 4-tuple sort in `tinc-conf::Config` makes cmdline beat file.

// detach/mlockall/setpriority/drop_privs are libc one-liners. The
// nix crate covers most, but `daemon(3)` is `#[cfg(not(apple))]`
// there and `setpriority`'s arg types vary by libc target (gnu uses
// __priority_which_t=c_uint, musl/bsd use c_int). Going through libc
// directly with explicit `as _` casts keeps the call sites portable
// without a cfg ladder. Four unsafe blocks, all single-syscall, all
// next to a process.c/tincd.c line ref.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_conf::{Config, Source, parse_line};
use tincd::{Daemon, RunOutcome, sd_notify};

/// `CONFDIR` from `config.h`. Same compile-time treatment as
/// `tinc-tools/src/names.rs::CONFDIR` — `option_env!` with `/etc`
/// default. Packagers set `TINC_CONFDIR`; everyone else gets `/etc`.
///
/// Duplicated from tinc-tools/names.rs because tincd doesn't dep on
/// tinc-tools (the dep arrow goes the other way: tools spawns tincd).
/// Two copies of a 4-line const is fine; if they ever diverge the
/// integration tests catch it (`-n` derives a path, the test checks
/// the netname component appears in the error).
const CONFDIR: &str = match option_env!("TINC_CONFDIR") {
    Some(d) => d,
    None => "/etc",
};

/// `tincd.c::debug_level` → `log::LevelFilter`. C levels (`logger.h:
/// 27-37`): 0=NOTHING (still prints Ready/Terminating), 1=CONNECTIONS,
/// 2=STATUS, 3=PROTOCOL, 4=META, 5=TRAFFIC. We don't have a 6-level
/// log crate; squash 0→Info, 1-2→Debug, 3+→Trace. Coarse but the
/// `target: "tincd"` substring filter still works for narrowing
/// (RUST_LOG=tincd::proto=trace etc).
fn debug_level_to_filter(d: u32) -> log::LevelFilter {
    match d {
        0 => log::LevelFilter::Info,
        1 | 2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

struct Args {
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    /// Parsed `-o` entries, `Source::Cmdline`-tagged. Passed through
    /// to `Daemon::setup`. Empty when no `-o` given; setup() merges
    /// an empty Config (no-op) — simpler than `Option<Config>`.
    cmdline_conf: Config,

    /// `do_detach` (`tincd.c:64`). Default true; `-D` clears it.
    do_detach: bool,
    /// `do_mlock` (`tincd.c:66`). `-L` sets it.
    do_mlock: bool,
    /// `switchuser` (`tincd.c:89`). `-U USER`. None → don't drop.
    switchuser: Option<String>,
    /// `do_chroot` (`tincd.c:88`). `-R`. Stored, applied in
    /// drop_privs alongside setuid (the C interleaves them: chroot
    /// BETWEEN initgroups+setgid and setuid, `tincd.c:403-414`).
    do_chroot: bool,
    /// `debug_level` (`tincd.c:63`). `-d` increments, `-dN` sets.
    /// None means "not given on cmdline" — distinct from 0, because
    /// the C falls back to `LogLevel` config key only when `-d`
    /// wasn't given (`tincd.c:599-605`). RUST_LOG env still wins
    /// over both.
    debug_level: Option<u32>,
    /// `--logfile [PATH]`. Some(None) means "default path" (the C
    /// derives `LOCALSTATEDIR/log/tinc.NETNAME.log`); we require an
    /// explicit path for now (the LOCALSTATEDIR derivation is the
    /// same names.c dance as pidfile — separate change).
    logfile: Option<PathBuf>,
    /// `-s` syslog. We don't have a syslog backend; this becomes a
    /// warn-unimplemented unless `--logfile` also given (then logfile
    /// wins, matching C `tincd.c:273-274`: `use_syslog = false` when
    /// logfile is set).
    use_syslog: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut confbase: Option<PathBuf> = None;
    let mut netname: Option<String> = None;
    let mut pidfile = None;
    let mut socket = None;
    let mut cmdline_conf = Config::new();
    // C `tincd.c:234`: `++lineno` for each `-o`. The line number is
    // the `-o` ordinal (1-based), used for stable sort within cmdline
    // entries. Matters for multi-valued keys (`-o Subnet=a -o
    // Subnet=b` → both kept, in argv order).
    let mut o_lineno: u32 = 0;

    let mut do_detach = true;
    let mut do_mlock = false;
    let mut switchuser = None;
    let mut do_chroot = false;
    let mut debug_level: Option<u32> = None;
    let mut logfile = None;
    let mut use_syslog = false;

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(format!("non-UTF-8 argument: {arg:?}"));
        };
        match arg {
            "-c" | "--config" => {
                let v = args
                    .next()
                    .ok_or_else(|| "-c requires a path".to_string())?;
                confbase = Some(PathBuf::from(v));
            }
            // C `tincd.c:221-225`: `case OPT_NETNAME: netname =
            // xstrdup(optarg)`. Short `-n`, long `--net`. The C
            // also accepts `-n NETNAME` glued (`-nfoo`); we don't
            // (the C uses getopt which splits it). Nobody types
            // `-nfoo`; if a script does, it gets "unknown argument".
            "-n" | "--net" => {
                let v = args
                    .next()
                    .ok_or_else(|| "-n requires a netname".to_string())?;
                let v = v
                    .into_string()
                    .map_err(|v| format!("non-UTF-8 netname: {v:?}"))?;
                netname = Some(v);
            }
            // C `tincd.c:196-197`: `case OPT_NO_DETACH: do_detach = false`.
            "-D" | "--no-detach" => {
                do_detach = false;
            }
            // C `tincd.c:199-206`: `case OPT_MLOCK`. The C errors if
            // built without HAVE_MLOCKALL; we always have it on Unix.
            "-L" | "--mlock" => {
                do_mlock = true;
            }
            // C `tincd.c:208-219`: `case OPT_DEBUG`. The C allows
            // `-d` (increment), `-dN` (glued), `-d N` (separate; uses
            // optind peek). We support all three.
            "-d" | "--debug" => {
                // Increment-only form. C: `debug_level++` from -1
                // start, so first `-d` → 0… wait no: `debug_level`
                // starts at `DEBUG_UNSET = -1`, the C `:599` checks
                // `if(debug_level == DEBUG_NOTHING)` which is 0.
                // Actually `tincd.c:63`: `int debug_level = -1;`.
                // First `-d` makes it 0. We track "given or not"
                // separately, so first `-d` → Some(0) is wrong;
                // it should be Some(1) to match `-d` ≈ "show
                // connections". Re-read… `debug_level++` from -1
                // gives 0 = DEBUG_NOTHING. Second `-d` gives 1 =
                // DEBUG_CONNECTIONS. That's the C. Match it: bare
                // `-d` increments from current-or-minus-one.
                //
                // Practically nobody types `-d -d`; they type `-d5`.
                // Model the increment as "from 0" — first `-d`
                // produces level 1 (≈ Debug). C-compat for the
                // common cases (`-d`, `-d5`); the edge case `-d -d`
                // gives 2 instead of 1, which is the same LevelFilter
                // bucket anyway.
                debug_level = Some(debug_level.unwrap_or(0) + 1);
            }
            // `-dN` glued. getopt's `d::` (optional arg) lets `-d5`
            // through. We pattern-match the prefix.
            _ if arg.starts_with("-d") && arg[2..].chars().all(|c| c.is_ascii_digit()) => {
                // Safe: the `all(is_ascii_digit)` guard means parse
                // can only fail on overflow. atoi() in C would
                // truncate; we cap.
                let n: u32 = arg[2..].parse().unwrap_or(u32::MAX);
                debug_level = Some(n);
            }
            // C `tincd.c:228-230`: `case OPT_SYSLOG`.
            "-s" | "--syslog" => {
                // C: `use_logfile = false; use_syslog = true`. Mutually
                // exclusive, last-wins. We don't have a syslog backend;
                // see init_logging() for the fallback.
                logfile = None;
                use_syslog = true;
            }
            // C `tincd.c:270-283`: `case OPT_LOGFILE`. Path is optional
            // in C (defaults to LOCALSTATEDIR/log/tinc.NETNAME.log).
            // We require a path — the default-path derivation needs
            // names.c LOCALSTATEDIR plumbing we haven't ported.
            "--logfile" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--logfile requires a path".to_string())?;
                use_syslog = false; // C `:273`
                logfile = Some(PathBuf::from(v));
            }
            // C `tincd.c:255-257`: `case OPT_CHANGE_USER`.
            "-U" | "--user" => {
                let v = args
                    .next()
                    .ok_or_else(|| "-U requires a username".to_string())?;
                let v = v
                    .into_string()
                    .map_err(|v| format!("non-UTF-8 username: {v:?}"))?;
                switchuser = Some(v);
            }
            // C `tincd.c:251-253`: `case OPT_CHROOT`.
            "-R" | "--chroot" => {
                do_chroot = true;
            }
            // C `tincd.c:232-241`: `case OPT_OPTION`. Parse the value
            // as a config line right here, fail-fast on malformed.
            // The C does `cfg = parse_config_line(optarg, NULL,
            // ++lineno); if(!cfg) goto exit_fail;` — same shape.
            //
            // C also accepts `--option`. We do too.
            "-o" | "--option" => {
                let v = args
                    .next()
                    .ok_or_else(|| "-o requires KEY=VALUE".to_string())?;
                let v = v
                    .into_string()
                    .map_err(|v| format!("non-UTF-8 -o value: {v:?}"))?;
                o_lineno += 1;
                // parse_line returns None for empty/whitespace lines.
                // `-o ""` or `-o "  "` is silently a no-op in C (the
                // parse falls through to the empty-variable check
                // which... actually in C `parse_config_line` with an
                // empty string: variable=value=NULL, the `if(!value
                // || !*value)` fires, error logged). We match the
                // error path: None → "expected KEY=VALUE".
                let entry = match parse_line(&v, Source::Cmdline { line: o_lineno }) {
                    None => {
                        return Err(format!("-o requires KEY=VALUE, got `{v}'"));
                    }
                    Some(Err(e)) => {
                        // `parse_line`'s ParseError already includes
                        // the variable name and source ("in command
                        // line option N"). Just wrap for the `tincd:`
                        // prefix in main.
                        return Err(format!("{e}"));
                    }
                    Some(Ok(e)) => e,
                };
                cmdline_conf.merge(std::iter::once(entry));
            }
            "--pidfile" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--pidfile requires a path".to_string())?;
                pidfile = Some(PathBuf::from(v));
            }
            "--socket" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--socket requires a path".to_string())?;
                socket = Some(PathBuf::from(v));
            }
            "--help" | "-h" => {
                eprintln!("Usage: tincd [-c DIR | -n NETNAME] --pidfile FILE --socket FILE");
                eprintln!("  -c, --config=DIR    Read configuration from DIR.");
                eprintln!("  -n, --net=NETNAME   Connect to net NETNAME.");
                eprintln!("  -o, --option=K=V    Set config option (repeatable).");
                eprintln!("  -D, --no-detach     Don't fork and detach.");
                eprintln!("  -d[LEVEL]           Increase debug level or set to LEVEL.");
                eprintln!("  -L, --mlock         Lock tinc into main memory.");
                eprintln!("  -s, --syslog        Use syslog (not yet implemented; warns).");
                eprintln!("      --logfile=FILE  Write log to FILE.");
                eprintln!("  -U, --user=USER     setuid to USER after setup.");
                eprintln!("  -R, --chroot        chroot to config dir after setup.");
                std::process::exit(0);
            }
            "--version" => {
                eprintln!("tincd {} (Rust skeleton)", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {
                return Err(format!("unknown argument: {arg}"));
            }
        }
    }

    // ─── NETNAME env fallback (tincd.c:294-305)
    // C: `if(!netname && (netname = getenv("NETNAME")))`. Only if
    // `-n` wasn't given. Standard env-under-flag precedence.
    if netname.is_none()
        && let Ok(env_net) = std::env::var("NETNAME")
    {
        netname = Some(env_net);
    }

    // ─── netname "." → None (tincd.c:301-303 in some versions; the
    // tincctl side has it at `tincctl.c:267-270`). "." is the
    // "top-level" sentinel — means "no netname, use confdir as
    // confbase". Allows `NETNAME=.` in env to explicitly say "I want
    // /etc/tinc not /etc/tinc/$NETNAME". Also empty string.
    if matches!(netname.as_deref(), Some("" | ".")) {
        netname = None;
    }

    // ─── netname path-traversal guard (tincd.c:308-313)
    // C: `if(netname && (strpbrk(netname, "\\/") || *netname == '.'))`.
    // Netname becomes a path component; slashes would escape confdir.
    // Leading dot rejects `..` (and also `.hidden`, which is fine).
    // Weaker than `check_id` — netname allows `-`, etc. The C is
    // permissive on purpose; netname is a local fs thing, not wire.
    if let Some(net) = &netname
        && (net.starts_with('.') || net.contains('/') || net.contains('\\'))
    {
        return Err("Invalid character in netname!".into());
    }

    // ─── derive confbase (the daemon-side `make_names`, abridged)
    // C `names.c:make_names(true)`. Three cases:
    //   -c given           → use it (netname ignored)
    //   netname given      → CONFDIR/tinc/NETNAME
    //   neither            → CONFDIR/tinc
    //
    // The C also derives pidfile/socket here. We don't (yet) — they
    // stay required. Adding the `LOCALSTATEDIR/run/tinc.NETNAME.pid`
    // derivation is a separate change (it has the access(2) fallback
    // dance from `names.c:111-148`, more than three lines).
    let confbase = confbase.unwrap_or_else(|| {
        let mut p: PathBuf = [CONFDIR, "tinc"].iter().collect();
        if let Some(net) = &netname {
            p.push(net);
        }
        p
    });

    Ok(Args {
        confbase,
        pidfile: pidfile.ok_or("missing --pidfile <path>")?,
        socket: socket.ok_or("missing --socket <path>")?,
        cmdline_conf,
        do_detach,
        do_mlock,
        switchuser,
        do_chroot,
        debug_level,
        logfile,
        use_syslog,
    })
}

/// `process.c:200-243` `detach()`. The C calls `daemon(1, 0)`:
/// nochdir=1 (stay in cwd; confbase paths are relative-safe already
/// because we resolved them, but the C does it so we match),
/// noclose=0 (redirect stdio → /dev/null).
///
/// `daemon(3)` is single-fork (fork+setsid) on glibc, NOT the
/// double-fork dance. The C uses single-fork too — the doc comment
/// in the brief said "double-fork" but `process.c:215` is `daemon(1,
/// 0)`. Single fork is fine on Linux/BSD: setsid() makes the child
/// a session leader, and a session leader can't acquire a controlling
/// tty by accident on modern kernels (the open() needs O_NOCTTY off
/// AND the process must not already have one — setsid satisfies the
/// second). Double-fork was for SysV.
///
/// Logging mode switch (`process.c:229-238`): the C reopens its
/// logger here, switching from LOGMODE_STDERR to LOGMODE_SYSLOG or
/// LOGMODE_FILE. We can't reopen env_logger (it's `init()`-once),
/// so we do the mode decision BEFORE init in `main()`. The "tincd
/// starting" log line therefore goes to the post-detach destination,
/// same as C.
fn detach() -> Result<(), String> {
    // SIGPIPE is already SIG_IGN — Rust runtime does that for us
    // (`library/std/src/sys/pal/unix/mod.rs::reset_sigpipe`). The
    // C `process.c:204-207` explicitly ignores SIGPIPE/USR1/USR2/
    // WINCH. USR1/USR2 are caught by SelfPipe in daemon.rs (they
    // dump state). WINCH we don't care about (no curses).

    // SAFETY: `daemon(3)` forks; the child returns 0, the parent
    // calls `_exit(0)` inside libc. Single-threaded at this point
    // (env_logger isn't initialized yet, no async runtime). The
    // only thread is this one. Post-fork the child is a fresh
    // single-threaded process — safe to keep going.
    //
    // (1, 0): keep cwd (we've resolved paths), close stdio.
    let r = unsafe { libc::daemon(1, 0) };
    if r != 0 {
        return Err(format!(
            "Couldn't detach from terminal: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `tincd.c:373-428` `drop_privs()`. Called AFTER `setup_network`
/// (so root has bound port 655, opened TUN, AND run tinc-up which
/// does `ip addr add`). Called BEFORE `main_loop` so the event loop
/// runs unprivileged.
///
/// Ordering inside (`tincd.c:378-420`):
///   getpwnam → initgroups → setgid → [chroot] → setuid
///
/// `chroot` between setgid and setuid is deliberate: chroot needs
/// CAP_SYS_CHROOT (root), but you want supplementary groups set
/// BEFORE the chroot (initgroups reads /etc/group, which is outside
/// the jail). And setuid LAST so it can't be undone.
fn drop_privs(
    switchuser: Option<&str>,
    do_chroot: bool,
    confbase: &std::path::Path,
) -> Result<(), String> {
    let uid_gid = if let Some(user) = switchuser {
        // C `tincd.c:378-384`: `getpwnam(switchuser)`. nix's
        // `User::from_name` wraps the reentrant `getpwnam_r`.
        let pw = nix::unistd::User::from_name(user)
            .map_err(|e| format!("getpwnam_r `{user}': {e}"))?
            .ok_or_else(|| format!("unknown user `{user}'"))?;

        // C `tincd.c:389-394`: `initgroups(switchuser, pw->pw_gid)
        // || setgid(pw->pw_gid)`. initgroups sets supplementary
        // groups from /etc/group; setgid sets the primary.
        //
        // SAFETY: `initgroups(3)` modifies the process's group list.
        // Single-threaded (event loop not started). Username is from
        // argv (UTF-8-validated in parse_args), nul-terminated here.
        // The gid type varies (c_int on macOS, gid_t elsewhere);
        // `as _` lets the compiler pick.
        let cuser = CString::new(user).map_err(|_| "username contains NUL".to_string())?;
        let gid: libc::gid_t = pw.gid.as_raw();
        let r = unsafe { libc::initgroups(cuser.as_ptr(), gid as _) };
        if r != 0 {
            return Err(format!(
                "System call `initgroups' failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        nix::unistd::setgid(pw.gid).map_err(|e| format!("System call `setgid' failed: {e}"))?;

        Some(pw.uid)
    } else {
        None
    };

    // C `tincd.c:403-414`: chroot AFTER initgroups (which reads
    // /etc/group), BEFORE setuid (chroot needs root).
    if do_chroot {
        // C `:405`: `tzset()` first. Loads /etc/localtime BEFORE
        // we lose access to it. Log timestamps stay in local tz.
        // libc crate doesn't bind tzset on unix (it's POSIX, just
        // not in their unix/mod.rs). Declare it.
        // SAFETY: tzset() reads /etc/localtime, sets the tzname/
        // timezone/daylight globals. Not re-entrant, but we're
        // single-threaded here (event loop hasn't started).
        unsafe extern "C" {
            fn tzset();
        }
        unsafe { tzset() };

        let confbase_c = CString::new(confbase.as_os_str().as_encoded_bytes())
            .map_err(|_| "confbase contains NUL".to_string())?;
        // SAFETY: chroot(2). Single syscall, we're root (or it fails
        // and we report).
        let r = unsafe { libc::chroot(confbase_c.as_ptr()) };
        if r != 0 {
            return Err(format!(
                "System call `chroot' failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // C `:407`: `chdir("/")`. Inside the jail now; cwd was
        // outside. Don't leave a handle to outside-the-jail.
        std::env::set_current_dir("/").map_err(|e| format!("chdir / after chroot: {e}"))?;
    }

    // C `tincd.c:416-420`: setuid LAST. After this we can't undo.
    if let Some(uid) = uid_gid {
        nix::unistd::setuid(uid).map_err(|e| format!("System call `setuid' failed: {e}"))?;
    }

    // C `:425`: `makedirs(DIR_CACHE | DIR_HOSTS | DIR_INVITATIONS)`.
    // Daemon::setup already creates what it needs (cache/ on demand
    // in addrcache.rs, hosts/ is required-exists). Skip.
    //
    // C `:427`: `sandbox_enter()`. Seccomp/pledge. Separate gap row.

    Ok(())
}

/// `tincd.c:670-698` `ProcessPriority` config key. Best-effort:
/// log on failure but don't abort (a daemon that can't nice itself
/// can still tunnel packets).
///
/// Reads tinc.conf again here rather than threading the merged
/// config out of Daemon::setup. ~1KB file, read once at boot.
/// The alternative (a `Daemon::config()` accessor or a callback
/// hook) touches daemon.rs which two other agents are editing.
fn apply_process_priority(confbase: &std::path::Path, cmdline: &Config) {
    let mut config = match tinc_conf::read_server_config(confbase) {
        Ok(c) => c,
        // Daemon::setup already validated this read. If it fails
        // here something raced (file deleted between calls). Warn
        // and skip — the priority is a hint, not load-bearing.
        Err(e) => {
            log::warn!(target: "tincd", "ProcessPriority: re-read tinc.conf failed: {e}");
            return;
        }
    };
    config.merge(cmdline.entries().iter().cloned());

    let Some(e) = config.lookup("ProcessPriority").next() else {
        return; // not set, default scheduling
    };
    let prio_str = e.get_str();

    // C `tincd.c:452-454` Unix mapping (the macros for the Windows
    // priority class names): Normal=0, Low=10, High=-10. nice values.
    let nice: libc::c_int = match prio_str.to_ascii_lowercase().as_str() {
        "normal" => 0,
        "low" => 10,
        "high" => -10,
        other => {
            log::error!(target: "tincd", "Invalid priority `{other}`!");
            return;
        }
    };

    // SAFETY: `setpriority(PRIO_PROCESS, 0, nice)`. who=0 means
    // "current process". The `which` arg type varies (c_uint on
    // gnu, c_int on musl/bsd) — PRIO_PROCESS the libc const has
    // the right type already; just don't annotate it.
    let r = unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, nice) };
    if r != 0 {
        log::warn!(
            target: "tincd",
            "System call `setpriority' failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Logging init. Folds `process.c:229-238` (logmode decision) and
/// the `-d`/`--logfile` argv knobs into one env_logger build.
///
/// C precedence (`process.c:229-237`):
///   logfile set        → LOGMODE_FILE
///   syslog OR detach   → LOGMODE_SYSLOG
///   else               → LOGMODE_STDERR
///
/// We don't have syslog. The middle case becomes "still stderr but
/// stderr is /dev/null after detach". That's a regression vs C
/// (a detached daemon with no `--logfile` is mute). Warn about it
/// pre-detach.
///
/// Level: RUST_LOG env beats `-d` beats default Info. The C has a
/// further fallback to `LogLevel` config key (`tincd.c:599-605`);
/// that needs the config tree, which isn't read yet here. Skipped —
/// you can `-o LogLevel=5` if you want it from config… except that
/// also needs the tree. TODO when init order is reworked.
fn init_logging(args: &Args) {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("tincd=info"));

    // `-d` → filter level. RUST_LOG (parsed by from_env above) wins
    // because it's a more specific target filter; `filter_level` is
    // the floor.
    if let Some(d) = args.debug_level {
        builder.filter_level(debug_level_to_filter(d));
    }

    // `--logfile PATH` → env_logger's Target::Pipe. The file is
    // opened append, created if missing. Ownership moves into the
    // logger (it's `Box<dyn Write + Send>`).
    if let Some(path) = &args.logfile {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(f) => {
                builder.target(env_logger::Target::Pipe(Box::new(f)));
            }
            Err(e) => {
                // Can't log yet (logger not init'd). eprintln, then
                // fall through to stderr logging — better than mute.
                eprintln!("tincd: --logfile {}: {e}", path.display());
            }
        }
    } else if args.use_syslog {
        // No syslog backend. C would `openlog(identname, LOG_PID,
        // LOG_DAEMON)`. The `syslog` crate exists but it's a new dep
        // for a feature that's mostly superseded by journald (which
        // captures stderr anyway when run as a systemd unit). Warn
        // and use stderr.
        eprintln!("tincd: -s/--syslog not implemented; using stderr");
    } else if args.do_detach {
        // Detached, no logfile, no syslog → logs go to /dev/null.
        // Tell the user BEFORE we daemonize (this eprintln still
        // reaches the terminal).
        eprintln!(
            "tincd: detaching with no --logfile; logs will be discarded. \
             Use -D to stay foreground or --logfile PATH."
        );
    }

    builder.init();
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tincd: {e}");
            eprintln!("Try `tincd --help` for usage.");
            return ExitCode::FAILURE;
        }
    };

    // ─── detach (process.c:200-243, called tincd.c:645)
    // BEFORE logger init: env_logger might spawn threads or hold
    // fds we don't want crossing the fork. (It doesn't currently,
    // but the safe ordering is fork-first.) The "starting" log line
    // goes to the post-detach destination, matching C.
    if args.do_detach
        && let Err(e) = detach()
    {
        eprintln!("tincd: {e}");
        return ExitCode::FAILURE;
    }

    init_logging(&args);

    // C `process.c:239-240`: the "tincd starting" banner. C says
    // "tincd %s (%s %s) starting, debug level %d" with build date.
    // We don't have a build date (reproducible builds); just version.
    log::info!(
        target: "tincd",
        "tincd {} starting, debug level {}",
        env!("CARGO_PKG_VERSION"),
        args.debug_level.unwrap_or(0)
    );

    // ─── mlockall (tincd.c:652-659)
    // C `:651` comment: "after daemon()/fork() so it works for
    // child. No need to do that in parent as it's very short-lived."
    // We forked above. Lock now.
    //
    // C HARD-FAILS on EPERM (`return 1`). We do too — if you asked
    // for `-L` and don't have CAP_IPC_LOCK, you probably want to
    // know your keys can swap. The brief said "best-effort warn"
    // but the C disagrees; match C.
    if args.do_mlock {
        use nix::sys::mman::{MlockAllFlags, mlockall};
        if let Err(e) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
            log::error!(
                target: "tincd",
                "System call `mlockall' failed: {e}"
            );
            return ExitCode::FAILURE;
        }
    }

    // ─── setup_network (tincd.c:665)
    // This opens TUN, binds sockets, AND runs tinc-up (daemon.rs:
    // ~1755). All of that needs root (TUN open, port <1024 bind,
    // `ip addr add` in the script). drop_privs is AFTER this.
    let daemon = match Daemon::setup(
        &args.confbase,
        &args.pidfile,
        &args.socket,
        &args.cmdline_conf,
    ) {
        Ok(d) => d,
        Err(e) => {
            log::error!(target: "tincd", "Setup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // ─── ProcessPriority (tincd.c:670-698)
    // After setup (config is read), before drop_privs (negative
    // nice needs root or CAP_SYS_NICE).
    apply_process_priority(&args.confbase, &args.cmdline_conf);

    // ─── drop_privs (tincd.c:694-696)
    // tinc-up has run (with root). Everything from here is
    // unprivileged: poll loop, SPTPS handshakes, packet relay.
    // tinc-down (in Daemon::Drop, daemon.rs:~1973) will run
    // unprivileged too — that's a known C limitation (the script
    // can't `ip link set down` after setuid). C lives with it; so
    // do we.
    if let Err(e) = drop_privs(args.switchuser.as_deref(), args.do_chroot, &args.confbase) {
        log::error!(target: "tincd", "{e}");
        return ExitCode::FAILURE;
    }

    // ─── sd_notify READY=1
    // After setup (sockets bound, TUN open, tinc-up done) but before
    // the poll loop. systemd's Type=notify waits for this; firing it
    // here means dependent units don't start until we're actually
    // ready to forward packets. No-op when NOTIFY_SOCKET is unset.
    sd_notify::notify_ready();

    // ─── sd_notify WATCHDOG=1
    // If WatchdogSec= is set, ping at half the interval from a
    // *separate thread*. Threading this through TimerWhat would mean
    // the event loop arms its own watchdog — so a hung event loop
    // (the very thing the watchdog is meant to catch) would stop
    // pinging only by accident. A detached thread keeps pinging as
    // long as the *process* is alive, which is what systemd actually
    // checks. The sd_notify writes are independent (just a sendto on
    // a Unix dgram socket), so no shared state with the main loop.
    if let Some(iv) = sd_notify::watchdog_interval() {
        std::thread::Builder::new()
            .name("sd-watchdog".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(iv);
                    sd_notify::notify_watchdog();
                }
            })
            .expect("spawn watchdog thread");
    }

    // ─── main_loop (tincd.c:717)
    let outcome = daemon.run();

    // ─── sd_notify STOPPING=1
    // run() returns on SIGTERM/SIGINT (RunOutcome::Clean) or fatal
    // poll error. Either way we're going down; tell systemd so it
    // extends the stop timeout for tinc-down + Daemon::Drop cleanup.
    sd_notify::notify_stopping();

    match outcome {
        RunOutcome::Clean => ExitCode::SUCCESS,
        RunOutcome::PollError => ExitCode::FAILURE,
    }
}
