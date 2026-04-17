//! tincd binary entry point.
//!
//! Hand-rolled argv (no clap; ~12 flags). `--socket` is a testability
//! addition (C derives it from `--pidfile`).
//!
//! ## C ordering (`tincd.c::main2`, `:640-720`)
//!
//! ```text
//! detach()           ← fork+setsid, switch logmode
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
//! `bool do_detach = true`. We MATCH that. This
//! breaks `cargo nextest` unless every spawned tincd gets `-D` —
//! which is what the C integration suite does too. The test helper
//! `tests/common/mod.rs::tincd_cmd()` bakes in `-D`. Anything that
//! spawns the daemon directly (rather than via the helper) needs to
//! pass `-D` itself; the crossimpl/throughput suites already do
//! (they were always passing `-D` to the C tincd; now both sides get it).
//!
//! ## `-n` / `-o`
//!
//! `-n NETNAME`: derives confbase from
//! `CONFDIR/tinc/NETNAME` when `-c` not given. The "run multiple
//! tinc instances" knob. NETNAME env var as fallback (`tincd.c:
//! 294-305`). The C calls `make_names()` to do the join; we inline
//! it (the daemon's `make_names` is simpler than tincctl's — no
//! pidfile fallback dance, daemon always wants explicit paths or
//! the standard one).
//!
//! `-o KEY=VALUE`: per-invocation config
//! overrides without editing tinc.conf. Repeatable. Parsed with
//! `tinc-conf::parse_line` (same parser as tinc.conf — `=` optional,
//! whitespace-separated works too: `-o "Port 655"`). Passed to
//! `Daemon::setup` which merges them with `Source::Cmdline`; the
//! 4-tuple sort in `tinc-conf::Config` makes cmdline beat file.

// detach/mlockall/drop_privs go through nix's safe wrappers
// (`daemon`/`initgroups`/`chroot`/`setgid`/`setuid`). Remaining
// unsafe: `setpriority` (nix 0.29 has no wrapper; arg types vary by
// libc target — gnu uses __priority_which_t=c_uint, musl/bsd c_int —
// so the raw call with `as _` is the portable form) and `tzset`
// (POSIX TZ-cache load, not bound by the libc crate on unix).
#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_conf::{Config, Source, parse_line};
use tincd::{Daemon, RunOutcome, sandbox, sd_notify};

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

/// `LOCALSTATEDIR` from `config.h`. Same compile-time pattern as
/// CONFDIR. Used for the default pidfile (
/// `LOCALSTATEDIR/run/tinc.NETNAME.pid`) and the default logfile
/// `LOCALSTATEDIR/log/tinc.NETNAME.log`). Duplicated
/// from `tinc-tools/src/names.rs:73` for the same dep-arrow reason
/// as CONFDIR above.
const LOCALSTATEDIR: &str = match option_env!("TINC_LOCALSTATEDIR") {
    Some(d) => d,
    None => "/var",
};

/// `tincd.c::debug_level` → `log::LevelFilter`. C levels (`logger.h:
/// 27-37`): 0=NOTHING (still prints Ready/Terminating), 1=CONNECTIONS,
/// 2=STATUS, 3=PROTOCOL, 4=META, 5=TRAFFIC. We don't have a 6-level
/// log crate; squash 0→Info, 1-2→Debug, 3+→Trace. Coarse but the
/// `target: "tincd"` substring filter still works for narrowing
/// (`RUST_LOG=tincd::proto=trace` etc).
const fn debug_level_to_filter(d: u32) -> log::LevelFilter {
    match d {
        0 => log::LevelFilter::Info,
        1 | 2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

#[allow(clippy::struct_excessive_bools)] // CLI flag bag, not a state machine
struct Args {
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    /// Parsed `-o` entries, `Source::Cmdline`-tagged. Passed through
    /// to `Daemon::setup`. Empty when no `-o` given; `setup()` merges
    /// an empty Config (no-op) — simpler than `Option<Config>`.
    cmdline_conf: Config,

    /// `do_detach`. Default true; `-D` clears it.
    do_detach: bool,
    /// `do_mlock`. `-L` sets it.
    do_mlock: bool,
    /// `switchuser`. `-U USER`. None → don't drop.
    switchuser: Option<String>,
    /// `do_chroot`. `-R`. Stored, applied in
    /// `drop_privs` alongside setuid (the C interleaves them: chroot
    /// BETWEEN initgroups+setgid and setuid).
    do_chroot: bool,
    /// `debug_level`. `-d` increments, `-dN` sets.
    /// None means "not given on cmdline" — distinct from 0, because
    /// the C falls back to `LogLevel` config key only when `-d`
    /// wasn't given. `RUST_LOG` env still wins
    /// over both.
    debug_level: Option<u32>,
    /// `--logfile [PATH]`. Bare `--logfile` (no arg) derives the C
    /// default `LOCALSTATEDIR/log/tinc.NETNAME.log`;
    /// the derivation happens post-loop in `parse_args` so it sees
    /// the final netname.
    logfile: Option<PathBuf>,
    /// `-s` syslog. We don't have a syslog backend; this becomes a
    /// warn-unimplemented unless `--logfile` also given (then logfile
    /// wins: `use_syslog = false` when
    /// logfile is set).
    use_syslog: bool,
}

/// Parse a `-o KEY=VALUE` argument. Factored out so the separated
/// (`-o K=V`) and glued (`--option=K=V`) match arms share the
/// parse_line+error-mapping; the `o_lineno` counter is owned by the
/// caller.
fn parse_o_arg(v: &str, o_lineno: u32) -> Result<tinc_conf::Entry, String> {
    match parse_line(v, Source::Cmdline { line: o_lineno }) {
        None => Err(format!("-o requires KEY=VALUE, got `{v}'")),
        Some(Err(e)) => Err(format!("{e}")),
        Some(Ok(e)) => Ok(e),
    }
}

/// Parse the value for a bare `-d` / `--debug` (no glued digits).
/// Handles two of the three forms C tincd accepts:
///
///   `-d 5`  separated — peek next argv, consume iff it's a number
///   `-d`    bare      — increment current level
///
/// (The third, glued `-d5`, is a separate match arm in `parse_args`
/// because it's a distinct argv string pattern.)
///
/// C semantics: `debug_level++` from `DEBUG_UNSET = -1`, so first
/// bare `-d` gives 0 = `DEBUG_NOTHING`, second gives 1. We model the
/// increment from 0 instead — first `-d` produces level 1. C-compat
/// for the common cases (`-d`, `-d5`); the edge case `-d -d` gives 2
/// instead of 1, which maps to the same `LevelFilter` bucket anyway.
///
/// The separated-arg peek mirrors C tincd's `argv[optind]` lookahead
/// gated on `*argv != '-'`: `-d -D` must NOT eat `-D` as the level.
/// The NixOS module emits `-d 0` as two argv entries; without this
/// the `0` would be "unknown argument".
fn parse_debug_arg<I>(current: Option<u32>, args: &mut std::iter::Peekable<I>) -> u32
where
    I: Iterator<Item = std::ffi::OsString>,
{
    if let Some(next) = args.peek()
        && let Some(s) = next.to_str()
        && !s.starts_with('-')
    {
        let n: u32 = s.parse().unwrap_or(0);
        args.next(); // consume it
        n
    } else {
        current.unwrap_or(0) + 1
    }
}

/// Pull the next argv element as the value for `flag`, decoding to
/// UTF-8. Factored out of the per-flag match arms: ~6 of them did
/// the same `next().ok_or().into_string().map_err()` dance with only
/// the error wording differing. The wording is now uniform; nobody
/// was relying on the old per-flag phrasing.
fn next_str(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires an argument"))?
        .into_string()
        .map_err(|v| format!("{flag}: non-UTF-8 argument: {}", v.display()))
}

#[allow(clippy::too_many_lines)] // flat getopt-style match; splitting per-option would scatter the C parity comments
fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut confbase: Option<PathBuf> = None;
    let mut netname: Option<String> = None;
    let mut pidfile = None;
    let mut socket = None;
    let mut cmdline_conf = Config::new();
    // `-o` ordinal (1-based), used for stable sort within cmdline
    // entries. Matters for multi-valued keys: `-o Subnet=a -o
    // Subnet=b` keeps both in argv order. The line number is
    // the `-o` ordinal (1-based), used for stable sort within cmdline
    // entries. Matters for multi-valued keys (`-o Subnet=a -o
    // Subnet=b` → both kept, in argv order).
    let mut o_lineno: u32 = 0;

    let mut do_detach = true;
    let mut do_mlock = false;
    let mut switchuser = None;
    let mut do_chroot = false;
    let mut debug_level: Option<u32> = None;
    // Tri-state during the loop: None = not given, Some(None) = bare
    // `--logfile` (derive default after we know netname), Some(Some(p))
    // = explicit path. Collapsed to Option<PathBuf> post-loop.
    let mut logfile: Option<Option<PathBuf>> = None;
    let mut use_syslog = false;

    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(format!("non-UTF-8 argument: {}", arg.display()));
        };
        match arg {
            "-c" | "--config" => {
                confbase = Some(PathBuf::from(next_str(&mut args, "-c")?));
            }
            // `--config=DIR` glued. `getopt_long` accepts the glued
            // form for every `required_argument` option; the NixOS
            // module's `tinc` wrapper uses it (`tinc.nix:473`).
            _ if arg.starts_with("--config=") => {
                confbase = Some(PathBuf::from(&arg["--config=".len()..]));
            }
            // `-cFOO` glued short form. C `getopt_long` accepts it for
            // every `required_argument` short option; scripts written
            // against C tincd use it (notably `-oKEY=VALUE`, which the
            // man page renders without a space). The `len() > 2` guard
            // keeps bare `-c` on the spaced arm above.
            _ if arg.starts_with("-c") && arg.len() > 2 => {
                confbase = Some(PathBuf::from(&arg[2..]));
            }
            "-n" | "--net" => {
                netname = Some(next_str(&mut args, "-n")?);
            }
            _ if arg.starts_with("--net=") => {
                netname = Some(arg["--net=".len()..].to_owned());
            }
            _ if arg.starts_with("-n") && arg.len() > 2 => {
                netname = Some(arg[2..].to_owned());
            }
            // `case OPT_NO_DETACH: do_detach = false`.
            "-D" | "--no-detach" => {
                do_detach = false;
            }
            // `case OPT_MLOCK`. Upstream errors if
            // built without HAVE_MLOCKALL; we always have it on Unix.
            "-L" | "--mlock" => {
                do_mlock = true;
            }
            // `case OPT_DEBUG`. Allows `-d` (increment), `-dN`
            // (glued), `-d N` (separate; uses optind peek). All three
            // supported; this arm covers the first and third, glued
            // forms are separate arms below. See parse_debug_arg.
            "-d" | "--debug" => {
                debug_level = Some(parse_debug_arg(debug_level, &mut args));
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
            // `--debug=N` glued long form. `getopt_long` accepts
            // this (the optstring `d::` plus `optional_argument` long
            // option). atoi-on-garbage gives 0; match that.
            _ if arg.starts_with("--debug=") => {
                debug_level = Some(arg["--debug=".len()..].parse().unwrap_or(0));
            }
            // `case OPT_SYSLOG`.
            "-s" | "--syslog" => {
                // `use_logfile = false; use_syslog = true`. Mutually
                // exclusive, last-wins. We don't have a syslog backend;
                // see init_logging() for the fallback.
                logfile = None;
                use_syslog = true;
            }
            // `case OPT_LOGFILE`. The optstring
            // marks this `optional_argument`: bare `--logfile` is VALID
            // and derives `LOCALSTATEDIR/log/tinc.NETNAME.log`
            // We peek the next arg gated on `*argv != '-'` —
            // `--logfile -d 5` must
            // NOT eat `-d` as the path. Same peek shape as `-d N`
            // above.
            "--logfile" => {
                use_syslog = false;
                if let Some(next) = args.peek()
                    && let Some(s) = next.to_str()
                    && !s.starts_with('-')
                {
                    let v = args.next().unwrap();
                    logfile = Some(Some(PathBuf::from(v)));
                } else {
                    // Bare form. Derive after the loop (netname may
                    // be set by a later `-n`).
                    logfile = Some(None);
                }
            }
            _ if arg.starts_with("--logfile=") => {
                use_syslog = false;
                logfile = Some(Some(PathBuf::from(&arg["--logfile=".len()..])));
            }
            // `case OPT_CHANGE_USER`.
            "-U" | "--user" => {
                switchuser = Some(next_str(&mut args, "-U")?);
            }
            _ if arg.starts_with("--user=") => {
                switchuser = Some(arg["--user=".len()..].to_owned());
            }
            _ if arg.starts_with("-U") && arg.len() > 2 => {
                switchuser = Some(arg[2..].to_owned());
            }
            // `case OPT_CHROOT`.
            "-R" | "--chroot" => {
                do_chroot = true;
            }
            // `case OPT_OPTION`. Parse the value
            // as a config line right here, fail-fast on malformed.
            // The C does `cfg = parse_config_line(optarg, NULL,
            // ++lineno); if(!cfg) goto exit_fail;` — same shape.
            //
            // C also accepts `--option`. We do too.
            "-o" | "--option" => {
                let v = next_str(&mut args, "-o")?;
                o_lineno += 1;
                cmdline_conf.merge(std::iter::once(parse_o_arg(&v, o_lineno)?));
            }
            // `--option=K=V` glued. The value itself contains `=`
            // (`--option=Port=655`); strip_prefix correctly leaves
            // `"Port=655"` for parse_line.
            _ if arg.starts_with("--option=") => {
                o_lineno += 1;
                let v = &arg["--option=".len()..];
                cmdline_conf.merge(std::iter::once(parse_o_arg(v, o_lineno)?));
            }
            // `-oKEY=VALUE` glued. The C man page renders the option
            // as `-o[HOST.]KEY=VALUE` (no space), so this form shows
            // up in real scripts.
            _ if arg.starts_with("-o") && arg.len() > 2 => {
                o_lineno += 1;
                cmdline_conf.merge(std::iter::once(parse_o_arg(&arg[2..], o_lineno)?));
            }
            "--pidfile" => {
                pidfile = Some(PathBuf::from(next_str(&mut args, "--pidfile")?));
            }
            _ if arg.starts_with("--pidfile=") => {
                pidfile = Some(PathBuf::from(&arg["--pidfile=".len()..]));
            }
            "--socket" => {
                socket = Some(PathBuf::from(next_str(&mut args, "--socket")?));
            }
            _ if arg.starts_with("--socket=") => {
                socket = Some(PathBuf::from(&arg["--socket=".len()..]));
            }
            "--help" | "-h" => {
                // stdout, not stderr: `tincd --help | less` must work
                // and C tincd writes usage to stdout (tincd.c:135).
                println!("Usage: tincd [option]...");
                println!();
                println!("  -c, --config=DIR        Read configuration from DIR.");
                println!("  -n, --net=NETNAME       Connect to net NETNAME.");
                println!("  -o, --option[=HOST.]K=V Set config option (repeatable).");
                println!("  -D, --no-detach         Don't fork and detach.");
                println!("  -d, --debug[=LEVEL]     Increase debug level or set to LEVEL.");
                println!("  -L, --mlock             Lock tinc into main memory.");
                println!("  -s, --syslog            Use syslog (not yet implemented; warns).");
                println!(
                    "      --logfile[=FILE]    Write log to FILE (default: {LOCALSTATEDIR}/log/tinc.NETNAME.log)."
                );
                println!("  -U, --user=USER         setuid to USER after setup.");
                println!("  -R, --chroot            chroot to config dir after setup.");
                println!("      --pidfile=FILE      Write PID and control cookie to FILE.");
                println!("      --socket=FILE       Bind control socket at FILE.");
                println!("      --help              Display this help and exit.");
                println!("      --version           Output version information and exit.");
                println!();
                println!("Report bugs to https://github.com/Mic92/tincr/issues.");
                std::process::exit(0);
            }
            "--version" => {
                // Same suffix as `tinc --version` so bug reports are
                // unambiguous about which implementation is running.
                println!(
                    "tincd {} (Rust) protocol {}.{}",
                    env!("CARGO_PKG_VERSION"),
                    tinc_proto::request::PROT_MAJOR,
                    tinc_proto::request::PROT_MINOR,
                );
                std::process::exit(0);
            }
            // C tincd accepts `--bypass-security`; this build doesn't
            // implement it (and shouldn't — it disables auth). Warn
            // instead of "unknown argument" so users following old
            // forum/wiki advice know the option was removed, not
            // mistyped. Same accept-and-warn shape as the
            // `generate-rsa-keys` stub in tinc-tools.
            "--bypass-security" => {
                eprintln!(
                    "tincd: Warning: --bypass-security is not supported in this build; ignoring."
                );
            }
            _ => {
                return Err(format!("unknown argument: {arg}"));
            }
        }
    }

    // ─── NETNAME env fallback
    // `if(!netname && (netname = getenv("NETNAME")))`. Only if
    // `-n` wasn't given. Standard env-under-flag precedence.
    if netname.is_none()
        && let Ok(env_net) = std::env::var("NETNAME")
    {
        netname = Some(env_net);
    }

    // ─── netname "." → None. "." is the
    // "top-level" sentinel — means "no netname, use confdir as
    // confbase". Allows `NETNAME=.` in env to explicitly say "I want
    // /etc/tinc not /etc/tinc/$NETNAME". Also empty string.
    if matches!(netname.as_deref(), Some("" | ".")) {
        netname = None;
    }

    // ─── netname path-traversal guard
    // `if(netname && (strpbrk(netname, "\\/") || *netname == '.'))`.
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
    // `make_names(true)`. Three cases:
    //   -c given           → use it (netname ignored)
    //   netname given      → CONFDIR/tinc/NETNAME
    //   neither            → CONFDIR/tinc
    //
    // Warn when both -c and -n are given. We
    // match the outcome (use -c) and the warning (logger isn't init'd
    // yet, eprintln).
    if confbase.is_some() && netname.is_some() {
        eprintln!(
            "tincd: Warning: both netname and configuration directory given, using the latter..."
        );
    }
    let confbase = confbase.unwrap_or_else(|| {
        let mut p: PathBuf = [CONFDIR, "tinc"].iter().collect();
        if let Some(net) = &netname {
            p.push(net);
        }
        p
    });

    // ─── identname: "tinc" or "tinc.NETNAME".
    // Shared by the logfile + pidfile derivations below.
    let identname = match &netname {
        Some(net) => format!("tinc.{net}"),
        None => "tinc".to_owned(),
    };

    // ─── derive logfile. Only when bare `--logfile`
    // was given (Some(None) above). Netname may have been set by a
    // later `-n`, hence post-loop.
    let logfile = logfile.map(|explicit| {
        explicit.unwrap_or_else(|| {
            [LOCALSTATEDIR, "log", &format!("{identname}.log")]
                .iter()
                .collect()
        })
    });

    // ─── derive pidfile (daemon=true branch).
    // `access(LOCALSTATEDIR, R_OK|W_OK|X_OK)` — if /var is
    // writable use `/var/run/tinc.NET.pid`; else fall back to
    // `{confbase}/pid` with a warning. The fallback
    // is for non-root daemons. `tinc start` and the NixOS module
    // both pass --pidfile explicitly so this only fires for the
    // tutorial `tincd -n foo` invocation.
    let pidfile = pidfile.unwrap_or_else(|| {
        use nix::unistd::{AccessFlags, access};
        let var_writable = access(
            LOCALSTATEDIR,
            AccessFlags::R_OK | AccessFlags::W_OK | AccessFlags::X_OK,
        )
        .is_ok();
        if var_writable {
            [LOCALSTATEDIR, "run", &format!("{identname}.pid")]
                .iter()
                .collect()
        } else {
            eprintln!(
                "tincd: cannot access {LOCALSTATEDIR}, storing pid/socket in {}",
                confbase.display()
            );
            confbase.join("pid")
        }
    });
    // ─── derive unixsocketname from pidfilename.
    // Strip `.pid` → `.socket`, else append. The NixOS module passes
    // only --pidfile; without this the unit dies "missing --socket".
    // `tinc -n NET` derives the same path on the CLI side.
    let socket = socket.unwrap_or_else(|| {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let p = pidfile.as_os_str().as_bytes();
        let stem = p.strip_suffix(b".pid").unwrap_or(p);
        let mut s = Vec::with_capacity(stem.len() + 7);
        s.extend_from_slice(stem);
        s.extend_from_slice(b".socket");
        PathBuf::from(std::ffi::OsString::from_vec(s))
    });

    Ok(Args {
        confbase,
        pidfile,
        socket,
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

/// `detach()`. Calls `daemon(1, 0)`:
/// nochdir=1 (stay in cwd; confbase paths are relative-safe already
/// because we resolved them, but the C does it so we match),
/// noclose=0 (redirect stdio → /dev/null).
///
/// `daemon(3)` is single-fork (fork+setsid) on glibc, NOT the
/// double-fork dance. The C uses single-fork too — the doc comment
/// in the brief said "double-fork" but the actual call is `daemon(1,
/// 0)`. Single fork is fine on Linux/BSD: `setsid()` makes the child
/// a session leader, and a session leader can't acquire a controlling
/// tty by accident on modern kernels (the `open()` needs `O_NOCTTY` off
/// AND the process must not already have one — setsid satisfies the
/// second). Double-fork was for `SysV`.
///
/// Logging mode switch: upstream reopens its
/// logger here, switching from `LOGMODE_STDERR` to `LOGMODE_SYSLOG` or
/// `LOGMODE_FILE`. We can't reopen `env_logger` (it's `init()`-once),
/// so we do the mode decision BEFORE init in `main()`. The "tincd
/// starting" log line therefore goes to the post-detach destination,
/// same as C.
/// Umbilical: parse env + snip.
///
/// `tinc start` does `socketpair`, forks, child gets `TINC_UMBILICAL
/// = "<fd> <colorize>"` in env, exec's tincd. The fd is the child end
/// of the socketpair. Parent reads from its end: any bytes before the
/// final nul are early-startup log lines (upstream
/// tees `real_logger` output to the umbilical so a detaching daemon's
/// startup errors reach `tinc start`'s stderr). The final nul byte
/// means "ready"; close means "done starting, go away".
///
/// We don't tee log output through the umbilical — `env_logger` doesn't
/// have a hook for it, and our "detached with no --logfile is mute"
/// warning (`init_logging`) already covers the lost-logs case. So this
/// function does only the snip half: write 1 nul byte, close.
///
/// `colorize` (the second int) drives the C's `format_pretty` for
/// teed log lines. We ignore it (no teeing).
///
/// The C parses the env *early* (`:549`, before `detach()`) but
/// writes *late* (`:702`, after `Ready`). The fd survives `daemon(3)`
/// because daemon(1, 0) only closes 0/1/2, and `tinc start` passes
/// fd ≥3 (it's a socketpair half, not stdio). We can do both halves
/// here in one place because we don't tee — nothing needs the fd
/// between parse and snip.
///
/// One irreducible `unsafe`: `OwnedFd::from_raw_fd`. The fd number
/// came from a string in an env var — asserting we *own* it (not
/// just that it's open) is a trust statement the type system can't
/// verify. `F_GETFL` probes that it's open; the env-var protocol is
/// the ownership proof. Same shape as systemd socket activation
/// (`LISTEN_FDS`): inherited fd, number in env, one unsafe to claim.
fn cut_umbilical() {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    let Ok(spec) = std::env::var("TINC_UMBILICAL") else {
        return;
    };
    // `sscanf(umbstr, "%d %d", &umbilical, &colorize)`.
    // First token is the fd. Second (colorize) we drop. sscanf with
    // one matched field returns 1 — the C doesn't check the return,
    // so a bare "%d" string (no second int) leaves colorize at its
    // initializer 0. Same here: only the first token matters.
    let Some(fd) = spec
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<std::os::fd::RawFd>().ok())
    else {
        return;
    };
    // Reject stdio (and negatives). C tinc's `if(fcntl(...)<0)
    // umbilical = 0` partially guarded this (fd 0 ≡ disabled);
    // we tighten to fd>2 — `tinc start` always passes a socketpair
    // half (≥3), and taking ownership of 0/1/2 via from_raw_fd
    // would close stdio and let the next open() reuse the slot.
    if fd <= 2 {
        log::warn!(target: "tincd",
            "TINC_UMBILICAL={spec}: fd {fd} is stdio/invalid, ignoring");
        return;
    }
    // Take ownership of the fd immediately. The TINC_UMBILICAL
    // protocol IS the ownership transfer — the spawner set the env
    // var to hand us this fd; nobody else in this process knows the
    // number. Drop closes it (the C's explicit `close(umbilical)`).
    //
    // SAFETY: fd > 2 checked above; the env var is the ownership
    // claim. If the fd is stale, the F_GETFL probe below catches it
    // and we drop (close) harmlessly.
    let f = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    if fcntl(&f, FcntlArg::F_GETFL).is_err() {
        return; // drop closes the fd
    }
    let _ = fcntl(&f, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
    let _ = nix::unistd::write(&f, b"\0");
    // Drop closes. snip!
}

fn detach() -> Result<(), String> {
    // SIGPIPE is already SIG_IGN — Rust runtime does that for us
    // (`library/std/src/sys/pal/unix/mod.rs::reset_sigpipe`).
    // USR1/USR2/WINCH are set to SIG_IGN in `register_signals`
    // (daemon/setup.rs); they no longer dump state — that moved
    // to the control socket in tinc 1.1.

    // `daemon(3)` forks; the child returns 0, the parent calls
    // `_exit(0)` inside libc. Single-threaded at this point
    // (env_logger isn't initialized yet, no async runtime). The
    // only thread is this one. Post-fork the child is a fresh
    // single-threaded process — safe to keep going.
    //
    // (nochdir=true, noclose=false): keep cwd (we've resolved
    // paths), close stdio.
    tincd::daemonize()
}

/// `drop_privs()`. Called AFTER `setup_network`
/// (so root has bound port 655, opened TUN, AND run tinc-up which
/// does `ip addr add`). Called BEFORE `main_loop` so the event loop
/// runs unprivileged.
///
/// Ordering inside:
///   getpwnam → initgroups → setgid → [chroot] → setuid
///
/// `chroot` between setgid and setuid is deliberate: chroot needs
/// `CAP_SYS_CHROOT` (root), but you want supplementary groups set
/// BEFORE the chroot (initgroups reads /etc/group, which is outside
/// the jail). And setuid LAST so it can't be undone.
fn drop_privs(
    switchuser: Option<&str>,
    do_chroot: bool,
    confbase: &std::path::Path,
) -> Result<(), String> {
    let uid_gid = if let Some(user) = switchuser {
        // `getpwnam(switchuser)`. nix's
        // `User::from_name` wraps the reentrant `getpwnam_r`.
        let pw = nix::unistd::User::from_name(user)
            .map_err(|e| format!("getpwnam_r `{user}': {e}"))?
            .ok_or_else(|| format!("unknown user `{user}'"))?;

        // `initgroups(switchuser, pw->pw_gid)
        // || setgid(pw->pw_gid)`. initgroups sets supplementary
        // groups from /etc/group; setgid sets the primary.
        //
        // `initgroups(3)` modifies the process's group list.
        // Single-threaded (event loop not started). Username is from
        // argv (UTF-8-validated in parse_args), nul-terminated here.
        let cuser = CString::new(user).map_err(|_| "username contains NUL".to_string())?;
        tincd::initgroups(&cuser, pw.gid)
            .map_err(|e| format!("System call `initgroups' failed: {e}"))?;
        #[cfg(target_os = "linux")]
        nix::unistd::setresgid(pw.gid, pw.gid, pw.gid)
            .map_err(|e| format!("System call `setresgid' failed: {e}"))?;
        #[cfg(not(target_os = "linux"))]
        nix::unistd::setgid(pw.gid).map_err(|e| format!("System call `setgid' failed: {e}"))?;

        Some((pw.uid, pw.gid))
    } else {
        None
    };

    // chroot AFTER initgroups (which reads
    // /etc/group), BEFORE setuid (chroot needs root).
    if do_chroot {
        // `tzset()` first. Loads /etc/localtime BEFORE
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

        nix::unistd::chroot(confbase).map_err(|e| format!("System call `chroot' failed: {e}"))?;
        // `chdir("/")`. Inside the jail now; cwd was
        // outside. Don't leave a handle to outside-the-jail.
        std::env::set_current_dir("/").map_err(|e| format!("chdir / after chroot: {e}"))?;
    }

    // setresuid LAST (real, effective, saved). After this we can't undo.
    if let Some((uid, gid)) = uid_gid {
        #[cfg(target_os = "linux")]
        {
            nix::unistd::setresuid(uid, uid, uid)
                .map_err(|e| format!("System call `setresuid' failed: {e}"))?;

            // Verify the kernel applied the drop to all three of each.
            let ru = nix::unistd::getresuid().map_err(|e| format!("getresuid: {e}"))?;
            let rg = nix::unistd::getresgid().map_err(|e| format!("getresgid: {e}"))?;
            if ru.real != uid || ru.effective != uid || ru.saved != uid {
                return Err(format!("setresuid did not stick: got {ru:?}, want {uid}"));
            }
            if rg.real != gid || rg.effective != gid || rg.saved != gid {
                return Err(format!("setresgid did not stick: got {rg:?}, want {gid}"));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = gid; // gid already set via setgid above
            nix::unistd::setuid(uid).map_err(|e| format!("System call `setuid' failed: {e}"))?;
        }
    }

    // PR_SET_NO_NEW_PRIVS: execve can't grant privileges (setuid
    // bits, file caps) from here on. Set unconditionally; the
    // sandbox path sets it again, harmlessly.
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        log::warn!(target: "tincd", "prctl(PR_SET_NO_NEW_PRIVS): {e}");
    }

    // `makedirs(DIR_CACHE | DIR_HOSTS | DIR_INVITATIONS)`.
    // Moved into sandbox::enter() (the Landlock arm) because the
    // pre-create is what makes the PathBeneath fd-open succeed.
    // Non-sandboxed runs don't need it (addrcache lazily mkdirs).
    //
    // `sandbox_enter()`. Done by the caller right after
    // this returns (main() owns the Paths struct).

    Ok(())
}

/// `ProcessPriority` config key. Best-effort:
/// log on failure but don't abort (a daemon that can't nice itself
/// can still tunnel packets).
///
/// Reads tinc.conf again here rather than threading the merged
/// config out of `Daemon::setup`. ~1KB file, read once at boot.
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

    // Unix mapping (the macros for the Windows
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

/// Logging init. Folds the logmode decision and
/// the `-d`/`--logfile` argv knobs into one `env_logger` build.
///
/// Precedence:
///   logfile set        → `LOGMODE_FILE`
///   syslog OR detach   → `LOGMODE_SYSLOG`
///   else               → `LOGMODE_STDERR`
///
/// We don't have syslog. The middle case becomes "still stderr but
/// stderr is /dev/null after detach". That's a regression vs C
/// (a detached daemon with no `--logfile` is mute). Warn about it
/// pre-detach.
///
/// Level: `RUST_LOG` env beats `-d` beats default Info. `LogLevel`
/// from `-o`/tinc.conf was already folded into `args.debug_level`
/// by [`resolve_debug_level`] before we get here.
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
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
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

    // Not `builder.init()`: the tap wraps the env_logger to forward
    // log lines to REQ_LOG control conns. `build()` then `log_tap::
    // init` does the same `set_boxed_logger` + `set_max_level` that
    // `init()` would, with our wrapper around it.
    let inner = builder.build();
    tincd::log_tap::init(inner);

    // Seed the C-style debug-level atomic so REQ_SET_DEBUG can
    // reply with the actual startup value (REQ_SET_DEBUG sends
    // `debug_level`; ours is in log_tap). `init_debug_level`, NOT
    // `set_debug_level`: the latter calls `log::set_max_level`,
    // which would clobber what `init()` just set from RUST_LOG.
    #[allow(clippy::cast_possible_wrap)] // debug_level is 0..=5 (CLI-validated)
    tincd::log_tap::init_debug_level(args.debug_level.map_or(0, |d| d as i32));
}

/// Consult the `LogLevel` config key when
/// `-d` was not given on argv. C's order is `read_server_config`
/// (`:591`) → `LogLevel` check (`:599`) → detach (`:640`). We had
/// logger-init BEFORE config-read; rather than reorder all of
/// init, read tinc.conf once here just for this key. The full
/// config gets re-read inside `Daemon::setup` anyway — one extra
/// ~1KB read at boot is free, and the alternative (delay logger
/// init until after setup) means setup errors land on a logger
/// that hasn't been told its level yet.
///
/// **Precedence** (first hit wins):
/// 1. `-d` / `--debug` argv
/// 2. `-o LogLevel=N` cmdline config
/// 3. `LogLevel = N` in tinc.conf
/// 4. None → caller defaults to Info
///
/// **C divergence:** C checks `debug_level == DEBUG_NOTHING` (0).
/// `debug_level` STARTS at -1 (wait: the logger global
/// says `DEBUG_NOTHING`; the *option* state at -1 is in tinc.c
/// pre-options, but `tincd.c` actually has `debug_level++` at
/// , and `debug_level` is the logger global =
/// `DEBUG_NOTHING` = 0). So: no `-d` → 0 → `LogLevel` read; bare
/// `-d` → 1 → NOT read; `-d5` → 5 → NOT read. That's the sane
/// thing. Our `is_none()` mirrors it exactly.
fn resolve_debug_level(args: &Args) -> Option<u32> {
    // Helper: pull LogLevel from a Config. get_int is i32 (C's
    // `get_config_int` writes an int); negative LogLevel is
    // nonsense, u32::try_from rejects it.
    fn lookup(c: &Config) -> Option<u32> {
        c.lookup("LogLevel")
            .next()
            .and_then(|e| e.get_int().ok())
            .and_then(|v| u32::try_from(v).ok())
    }

    if args.debug_level.is_some() {
        return args.debug_level; // -d wins
    }

    // -o LogLevel= first. Source::Cmdline beats file in tinc-conf's
    // 4-tuple sort, but we're not merging here so be explicit.
    if let Some(v) = lookup(&args.cmdline_conf) {
        return Some(v);
    }

    // tinc.conf. Read failure → silently None: logger isn't init'd
    // yet to report it, and Daemon::setup will hit the same failure
    // and report it properly. Upstream returns 1 on parse failure
    // but ALSO before its logger switches mode — same shape.
    tinc_conf::read_server_config(&args.confbase)
        .ok()
        .and_then(|c| lookup(&c))
}

/// `read_sandbox_level`. Same early-read shape as
/// `resolve_debug_level`: tinc.conf is re-read here just for this
/// key. C reads it AFTER `read_server_config` (`:595`), BEFORE
/// detach. We read it after detach (the file read crosses `fork()`
/// fine) but before logger init would be too early to report parse
/// errors; after `init_logging` is the right spot.
///
/// Default `none`. Upstream uses `normal` when `HAVE_SANDBOX`
/// (OpenBSD), else `none`. We're the non-OpenBSD case: explicit
/// opt-in. Landlock is always compiled in on Linux but the DEFAULT
/// stays `none` so an unconfigured daemon behaves as before.
///
/// `-o Sandbox=` cmdline override beats tinc.conf same as `LogLevel`.
fn resolve_sandbox_level(
    confbase: &std::path::Path,
    cmdline: &Config,
) -> Result<sandbox::Level, String> {
    fn lookup(c: &Config) -> Option<Result<sandbox::Level, String>> {
        c.lookup("Sandbox").next().map(|e| {
            sandbox::Level::parse(e.get_str()).map_err(|v| format!("Bad sandbox value {v}!"))
        })
    }
    if let Some(r) = lookup(cmdline) {
        return r;
    }
    // tinc.conf re-read. Same silent-on-read-fail as
    // resolve_debug_level: Daemon::setup will surface the real error.
    if let Ok(c) = tinc_conf::read_server_config(confbase)
        && let Some(r) = lookup(&c)
    {
        return r;
    }
    Ok(sandbox::Level::None)
}

/// `LISTEN_PID`/`LISTEN_FDS` env-var parse, factored out for
/// testability.
/// Takes the env values as parameters so tests can inject them
/// without `set_var` (which is `unsafe` since 1.85 and racy under
/// nextest's shared-process model).
///
/// The PID check IS the security gate. systemd sets `LISTEN_PID` to
/// the pid it forked. If we got the var by inheritance (a wrapper
/// script `exec`'d us, or we were forked WITHOUT exec from something
/// that had it set), the PID won't match → ignore. Without this
/// check, a stale `LISTEN_FDS=3` in the env would make us treat
/// fds 3..N as listen sockets even when they're a logfile / pipe /
/// garbage.
///
/// Returns `Some(n)` only when BOTH the PID matches AND `LISTEN_FDS`
/// parses as a positive count. C splits the two checks across
/// We fuse the two checks here because
/// main.rs needs the answer BEFORE the detach decision.
fn check_socket_activation(
    listen_pid: Option<String>,
    listen_fds: Option<String>,
) -> Option<usize> {
    let pid_ok = listen_pid.and_then(|s| s.parse::<u32>().ok()) == Some(std::process::id());
    if !pid_ok {
        return None;
    }
    listen_fds
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
}

fn main() -> ExitCode {
    let mut args = match parse_args(std::env::args_os().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tincd: {e}");
            eprintln!("Try `tincd --help` for usage.");
            return ExitCode::FAILURE;
        }
    };

    // `chdir(confbase)`. Hard-fail (`return 1`).
    // User-visible: tinc-up/tinc-down/host-* scripts inherit this
    // as their cwd (script execution does no chdir of its own; the
    // daemon's cwd IS the script's cwd). A `tinc-up` doing
    // `cat hosts/$NODE` works under C only because of this.
    //
    // We could `.current_dir(&confbase)` per-script in script.rs
    // instead (more surgical, doesn't touch the daemon's own cwd).
    // But: (a) /proc/self/cwd would differ from C, breaking ops
    // debugging assumptions, (b) any future code that opens a
    // relative path would silently work-under-C-break-under-us.
    // One process-level chdir matches C exactly.
    //
    // BEFORE detach.
    // `daemon(1, 0)` is nochdir=1 (preserves cwd across fork).
    // Our detach() does the same — the only set_current_dir is
    // post-chroot at `:721`.
    //
    // `-R` chroot: `drop_privs` later does `chdir("/")` AFTER
    // chroot. That overrides this. cwd = jail root = confbase-
    // as-seen-from-inside. Scripts still find `hosts/`.
    if let Err(e) = std::env::set_current_dir(&args.confbase) {
        // Logger not init'd yet. C uses `logger(DEBUG_ALWAYS,
        // LOG_ERR)` which at this point goes to stderr
        // (LOGMODE_STDERR until `:572` openlogger). eprintln matches.
        eprintln!(
            "Could not change to configuration directory {}: {e}",
            args.confbase.display()
        );
        return ExitCode::FAILURE;
    }

    // ─── socket activation
    // BEFORE detach: socket-activated daemons don't fork (systemd
    // already daemonized; another fork would orphan the fds — the
    // child has a new PID, LISTEN_PID won't match in the child, but
    // C clears do_detach BEFORE the fork so the fork never happens).
    //
    // The unsafe `remove_var`: glibc's setenv/getenv aren't thread-
    // safe. We're pre-detach, pre-logger, pre-everything; the only
    // thread is this one. Safe by construction.
    let socket_activation = check_socket_activation(
        std::env::var("LISTEN_PID").ok(),
        std::env::var("LISTEN_FDS").ok(),
    );
    // unsetenv. Don't leak to tinc-up.
    // SAFETY: single-threaded (see above). remove_var is documented
    // unsafe only because of glibc's non-reentrant getenv; with no
    // concurrent readers there's nothing to race.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
    }
    if socket_activation.is_some() {
        // `do_detach = false`.
        args.do_detach = false;
    }

    // ─── detach
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

    // Fold tinc.conf's `LogLevel` into args.debug_level BEFORE the
    // logger comes up (and before the seed at init_logging's tail,
    // so REQ_SET_DEBUG sees it too). After detach is fine: file
    // reads cross fork() safely. C does it before detach (`:599`
    // vs `:640`) but the order doesn't change anything observable.
    args.debug_level = resolve_debug_level(&args);

    init_logging(&args);

    // The "tincd starting" banner. Upstream says
    // "tincd %s (%s %s) starting, debug level %d" with build date.
    // We don't have a build date (reproducible builds); just version.
    log::info!(
        target: "tincd",
        "tincd {} starting, debug level {}",
        env!("CARGO_PKG_VERSION"),
        args.debug_level.unwrap_or(0)
    );

    // ─── mlockall
    // "after daemon()/fork() so it works for
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

    // ─── setup_network
    // This opens TUN, binds sockets, AND runs tinc-up (daemon.rs:
    // ~1755). All of that needs root (TUN open, port <1024 bind,
    // `ip addr add` in the script). drop_privs is AFTER this.
    let daemon = match Daemon::setup(
        &args.confbase,
        &args.pidfile,
        &args.socket,
        &args.cmdline_conf,
        socket_activation,
    ) {
        Ok(d) => d,
        Err(e) => {
            log::error!(target: "tincd", "Setup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // ─── ProcessPriority
    // After setup (config is read), before drop_privs (negative
    // nice needs root or CAP_SYS_NICE).
    apply_process_priority(&args.confbase, &args.cmdline_conf);

    // ─── drop_privs
    // tinc-up has run (with root). Everything from here is
    // unprivileged: poll loop, SPTPS handshakes, packet relay.
    // tinc-down (in Daemon::Drop, daemon.rs:~1973) will run
    // unprivileged too — that's a known C limitation (the script
    // can't `ip link set down` after setuid). C lives with it; so
    // do we.
    if let Err(e) = drop_privs(args.switchuser.as_deref(), args.do_chroot, &args.confbase) {
        log::error!(target: "tincd", "{e}");
        // Hard exit: do NOT unwind through Daemon::Drop (which runs
        // tinc-down/subnet-down) with privileges in an unknown state.
        std::process::exit(1);
    }

    // ─── sandbox_enter
    // AFTER drop_privs (the C order). tinc-up has run; device is
    // open; listeners are bound. Everything from here is the epoll
    // loop, which only touches confbase (hosts/, cache/), the
    // device fd (already open — Landlock doesn't gate fd I/O), and
    // the pidfile/socket on Drop.
    //
    // Device path: hard-coded /dev/net/tun on Linux. tinc-device's
    // DEFAULT_DEVICE is private but every Linux backend opens that
    // one path. The fd is already held; this rule is for the
    // (theoretical) case of a re-open mid-run, which doesn't
    // happen. Upstream unveils it anyway; we match.
    // dummy/fd device types pass None (no path-based open).
    let sandbox_level = match resolve_sandbox_level(&args.confbase, &args.cmdline_conf) {
        Ok(l) => l,
        Err(e) => {
            log::error!(target: "tincd", "{e}");
            return ExitCode::FAILURE;
        }
    };
    let sandbox_paths = sandbox::Paths {
        confbase: args.confbase.clone(),
        #[cfg(target_os = "linux")]
        device: Some("/dev/net/tun".into()),
        #[cfg(not(target_os = "linux"))]
        device: None,
        logfile: args.logfile.clone(),
        pidfile: args.pidfile.clone(),
        unixsocket: args.socket.clone(),
    };
    if let Err(e) = sandbox::enter(sandbox_level, &sandbox_paths, args.do_chroot) {
        log::error!(target: "tincd", "{e}");
        return ExitCode::FAILURE;
    }

    // ─── sd_notify READY=1
    // After setup (sockets bound, TUN open, tinc-up done) but before
    // the poll loop. systemd's Type=notify waits for this; firing it
    // here means dependent units don't start until we're actually
    // ready to forward packets. No-op when NOTIFY_SOCKET is unset.
    sd_notify::notify_ready();

    // ─── umbilical snip
    // Sibling of sd_notify: same "daemon is up" signal, different
    // consumer. `tinc start` forks us with TINC_UMBILICAL=<fd> in
    // env, then blocks reading that fd. The single nul byte we write
    // here is the "ready" handshake; closing the fd lets `tinc
    // start` exit 0. No-op when TINC_UMBILICAL is unset (the normal
    // case — systemd, manual start, tests all spawn directly).
    cut_umbilical();

    // ─── sd_notify WATCHDOG=1
    // Armed as `TimerWhat::Watchdog` inside `Daemon::setup` so a
    // wedged event loop stops pinging and systemd actually restarts
    // us. (A detached thread here would keep pinging through a hang,
    // defeating the point of WatchdogSec.)

    // ─── main_loop
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn argv(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn debug_glued_long() {
        let a = parse_args(argv(&["--debug=5", "-c", "/tmp", "--pidfile=/tmp/p"])).unwrap();
        assert_eq!(a.debug_level, Some(5));
    }

    #[test]
    fn debug_glued_garbage_is_atoi_zero() {
        let a = parse_args(argv(&["--debug=garbage", "-c", "/tmp", "--pidfile=/tmp/p"])).unwrap();
        assert_eq!(a.debug_level, Some(0));
    }

    #[test]
    fn config_glued() {
        let a = parse_args(argv(&["--config=/foo", "--pidfile=/tmp/p"])).unwrap();
        assert_eq!(a.confbase, PathBuf::from("/foo"));
    }

    #[test]
    fn net_glued_derives_confbase() {
        let a = parse_args(argv(&["--net=myvpn", "--pidfile=/tmp/p"])).unwrap();
        assert!(a.confbase.ends_with("tinc/myvpn"));
    }

    #[test]
    fn option_glued_with_embedded_equals() {
        let a = parse_args(argv(&[
            "--option=Port=1234",
            "--pidfile=/tmp/p",
            "-c",
            "/tmp",
        ]))
        .unwrap();
        // The value itself contains `=`; strip_prefix should leave "Port=1234".
        assert!(a.cmdline_conf.lookup("Port").next().is_some());
    }

    /// Glued short options (`-cFOO`, `-nFOO`, `-oK=V`, `-UFOO`): C
    /// `getopt_long` accepts these and existing scripts rely on the
    /// `-oKEY=VALUE` form the man page documents.
    #[test]
    fn short_options_glued() {
        let a = parse_args(argv(&["-c/tmp/conf", "--pidfile=/tmp/p"])).unwrap();
        assert_eq!(a.confbase, PathBuf::from("/tmp/conf"));

        let a = parse_args(argv(&["-nmesh", "--pidfile=/tmp/p"])).unwrap();
        assert!(a.confbase.ends_with("tinc/mesh"));

        let a = parse_args(argv(&["-Unobody", "--pidfile=/tmp/p", "-c", "/tmp"])).unwrap();
        assert_eq!(a.switchuser.as_deref(), Some("nobody"));

        let a = parse_args(argv(&["-oPort=1234", "--pidfile=/tmp/p", "-c", "/tmp"])).unwrap();
        assert!(a.cmdline_conf.lookup("Port").next().is_some());
    }

    #[test]
    fn user_glued() {
        let a = parse_args(argv(&["--user=nobody", "--pidfile=/tmp/p", "-c", "/tmp"])).unwrap();
        assert_eq!(a.switchuser.as_deref(), Some("nobody"));
    }

    #[test]
    fn logfile_bare_does_not_eat_next_flag() {
        // Regression: old code did `args.next()` unconditionally and
        // would consume `-d` as the logfile path. C peeks gated on
        // `*argv != '-'`.
        let a = parse_args(argv(&[
            "--logfile",
            "-d",
            "5",
            "--pidfile=/tmp/p",
            "-c",
            "/tmp",
        ]))
        .unwrap();
        assert!(a.logfile.is_some(), "bare --logfile derives a default");
        assert_ne!(a.logfile.as_deref(), Some(std::path::Path::new("-d")));
        assert_eq!(a.debug_level, Some(5));
    }

    #[test]
    fn logfile_separated() {
        let a = parse_args(argv(&[
            "--logfile",
            "/tmp/log",
            "--pidfile=/tmp/p",
            "-c",
            "/tmp",
        ]))
        .unwrap();
        assert_eq!(a.logfile.as_deref(), Some(std::path::Path::new("/tmp/log")));
    }

    #[test]
    fn logfile_glued() {
        let a = parse_args(argv(&[
            "--logfile=/tmp/log",
            "--pidfile=/tmp/p",
            "-c",
            "/tmp",
        ]))
        .unwrap();
        assert_eq!(a.logfile.as_deref(), Some(std::path::Path::new("/tmp/log")));
    }

    #[test]
    fn logfile_bare_derives_from_netname() {
        // `--logfile` precedes `-n`; derivation must use the final
        // netname (post-loop, like C make_names).
        let a = parse_args(argv(&["--logfile", "-n", "foo", "--pidfile=/tmp/p"])).unwrap();
        assert!(a.logfile.unwrap().ends_with("log/tinc.foo.log"));
    }

    #[test]
    fn pidfile_derived_when_absent() {
        // No --pidfile given. Must derive SOMETHING (either
        // /var/run/tinc.foo.pid or {confbase}/pid depending on /var
        // writability) instead of erroring out. Don't assert the
        // exact path — test runner may or may not have /var access.
        let a = parse_args(argv(&["-n", "foo", "-c", "/tmp"])).unwrap();
        assert!(
            a.pidfile.ends_with("tinc.foo.pid") || a.pidfile.ends_with("pid"),
            "derived pidfile {:?}",
            a.pidfile
        );
    }

    #[test]
    fn both_c_and_n_uses_c() {
        // -c wins, warning to stderr (not asserted here).
        let a = parse_args(argv(&["-c", "/tmp", "-n", "foo", "--pidfile=/tmp/p"])).unwrap();
        assert_eq!(a.confbase, PathBuf::from("/tmp"));
    }

    #[test]
    fn pidfile_glued() {
        let a = parse_args(argv(&["--pidfile=/tmp/custom.pid", "-c", "/tmp"])).unwrap();
        assert_eq!(a.pidfile, PathBuf::from("/tmp/custom.pid"));
        // Socket still derived from pidfile.
        assert_eq!(a.socket, PathBuf::from("/tmp/custom.socket"));
    }

    #[test]
    fn socket_glued() {
        let a = parse_args(argv(&["--socket=/tmp/s", "--pidfile=/tmp/p", "-c", "/tmp"])).unwrap();
        assert_eq!(a.socket, PathBuf::from("/tmp/s"));
    }

    // ─── resolve_debug_level

    // Hand-rolled tempdir (matches tests/common/mod.rs::TmpGuard;
    // no tempfile dep in this crate). PID+TID → nextest-parallel-safe.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!(
                "tincd-loglevel-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn args_at(confbase: PathBuf) -> Args {
        // pidfile/socket don't matter here; -c sets confbase.
        let mut a = parse_args(argv(&["--pidfile=/tmp/p"])).unwrap();
        a.confbase = confbase;
        a
    }

    #[test]
    fn loglevel_d_flag_wins() {
        let t = Tmp::new("d-wins");
        std::fs::write(t.0.join("tinc.conf"), "LogLevel = 3\n").unwrap();
        let mut a = args_at(t.0.clone());
        a.debug_level = Some(5);
        assert_eq!(resolve_debug_level(&a), Some(5));
    }

    #[test]
    fn loglevel_from_cmdline_o() {
        // No tinc.conf on disk → if this passes, we know -o was
        // checked BEFORE the file (and the file read short-circuited).
        let a = parse_args(argv(&[
            "-o",
            "LogLevel=3",
            "-c",
            "/nonexistent/tincd-loglevel-test",
            "--pidfile=/tmp/p",
        ]))
        .unwrap();
        assert_eq!(a.debug_level, None);
        assert_eq!(resolve_debug_level(&a), Some(3));
    }

    #[test]
    fn loglevel_from_tinc_conf() {
        let t = Tmp::new("from-conf");
        std::fs::write(t.0.join("tinc.conf"), "LogLevel = 4\n").unwrap();
        let a = args_at(t.0.clone());
        assert_eq!(resolve_debug_level(&a), Some(4));
    }

    #[test]
    fn loglevel_absent_everywhere() {
        let t = Tmp::new("absent");
        std::fs::write(t.0.join("tinc.conf"), "Name = foo\n").unwrap();
        let a = args_at(t.0.clone());
        assert_eq!(resolve_debug_level(&a), None);
    }

    #[test]
    fn loglevel_missing_tinc_conf_is_silent() {
        let a = args_at(PathBuf::from("/nonexistent/tincd-loglevel-test"));
        assert_eq!(resolve_debug_level(&a), None); // no panic
    }

    #[test]
    fn loglevel_negative_rejected() {
        // C get_config_int would happily set debug_level = -2. We
        // route through u32::try_from → None → default Info. Stricter
        // than C; nonsense input gets nonsense (default) output.
        let t = Tmp::new("neg");
        std::fs::write(t.0.join("tinc.conf"), "LogLevel = -2\n").unwrap();
        let a = args_at(t.0.clone());
        assert_eq!(resolve_debug_level(&a), None);
    }

    // ─── check_socket_activation

    /// PID matching ours + `LISTEN_FDS=2` → Some(2). The happy path.
    #[test]
    fn socket_activation_our_pid_with_fds() {
        let our = std::process::id().to_string();
        assert_eq!(
            check_socket_activation(Some(our), Some("2".into())),
            Some(2)
        );
    }

    /// Wrong PID → None even with valid `LISTEN_FDS`. THE security
    /// gate — inheritance from a wrapper that happened to have the
    /// vars set must not make us adopt random fds.
    #[test]
    fn socket_activation_wrong_pid_ignored() {
        // Our PID + 1 is guaranteed not-us (PIDs are unique).
        let wrong = (std::process::id() + 1).to_string();
        assert_eq!(check_socket_activation(Some(wrong), Some("2".into())), None);
    }

    /// Right PID but no `LISTEN_FDS` → None. Upstream
    /// gates on `listen_fds` non-null too.
    #[test]
    fn socket_activation_no_fds() {
        let our = std::process::id().to_string();
        assert_eq!(check_socket_activation(Some(our), None), None);
    }

    /// `LISTEN_FDS=0` → None. Zero sockets is not activation.
    #[test]
    fn socket_activation_zero_fds() {
        let our = std::process::id().to_string();
        assert_eq!(check_socket_activation(Some(our), Some("0".into())), None);
    }

    /// Garbage in either var → None. C uses `atoi` (returns 0 on
    /// garbage); 0 != `getpid()` and 0 fds is filtered. Same outcome.
    #[test]
    fn socket_activation_garbage() {
        let our = std::process::id().to_string();
        assert_eq!(
            check_socket_activation(Some("garbage".into()), Some("2".into())),
            None
        );
        assert_eq!(
            check_socket_activation(Some(our), Some("garbage".into())),
            None
        );
    }

    /// Neither var set → None. The common case (not socket-activated).
    #[test]
    fn socket_activation_absent() {
        assert_eq!(check_socket_activation(None, None), None);
    }
}
