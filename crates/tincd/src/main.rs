//! tincd binary entry point.
//!
//! Boot ordering (matches C `tincd.c::main2`):
//!     detach → mlockall → setup_network (binds + tinc-up as root)
//!     → ProcessPriority → drop_privs → main_loop.
//!
//! `-D` (no-detach) is required for the test suite; `tests/common/
//! mod.rs::tincd_cmd()` sets it. `-n NETNAME` (or `NETNAME` env)
//! derives confbase as `CONFDIR/tinc/NETNAME`. `-o KEY=VALUE` is
//! parsed via `tinc-conf::parse_line` and merged with `Source::
//! Cmdline` so it beats file values.

// New unsafe in the entrypoint should trip the lint; remaining
// per-site uses carry an explicit `#[allow(unsafe_code)]`.
#![deny(unsafe_code)]

use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_conf::{Config, Source, parse_line};
use tincd::{Daemon, RunOutcome, sandbox, sd_notify};

/// `CONFDIR` from `config.h`; packagers override via `TINC_CONFDIR`.
/// Duplicated in `tinc-tools/src/names.rs` (the dep arrow goes the
/// other way).
const CONFDIR: &str = match option_env!("TINC_CONFDIR") {
    Some(d) => d,
    None => "/etc",
};

/// `LOCALSTATEDIR` from `config.h`; default for pidfile/logfile.
const LOCALSTATEDIR: &str = match option_env!("TINC_LOCALSTATEDIR") {
    Some(d) => d,
    None => "/var",
};

/// Map C debug levels (0=NOTHING through 5=TRAFFIC) onto Rust's
/// 3-level filter. `target: "tincd"` filtering via `RUST_LOG`
/// recovers finer granularity.
const fn debug_level_to_filter(d: u32) -> log::LevelFilter {
    match d {
        0 => log::LevelFilter::Info,
        1 | 2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

#[allow(clippy::struct_excessive_bools)] // mirrors C tincd's flat `do_*` globals
struct Args {
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    /// `-o` entries, `Source::Cmdline`-tagged. Empty when none given.
    cmdline_conf: Config,

    /// `-D` clears (default true).
    do_detach: bool,
    /// `-L`.
    do_mlock: bool,
    /// `--allow-coredump` / `TINCR_ALLOW_COREDUMP=1`. Opts out of
    /// [`harden_process`] so `coredumpctl gdb` works.
    allow_coredump: bool,
    /// `-U USER`. None → don't drop.
    switchuser: Option<String>,
    /// `-R`. Applied inside `drop_privs` between setgid and setuid.
    do_chroot: bool,
    /// `-d` / `--debug`. None means "not given" — distinct from 0,
    /// because the `LogLevel` tinc.conf fallback only fires when
    /// `-d` was absent. `RUST_LOG` still wins over both.
    debug_level: Option<u32>,
    /// `--logfile [PATH]`; bare form derives
    /// `LOCALSTATEDIR/log/tinc.NETNAME.log` post-loop.
    logfile: Option<PathBuf>,
    /// Default sink for the detach-with-no-`--logfile` fallback.
    /// Applied in `main()` after socket activation has finalised
    /// `do_detach`, not in `parse_args`.
    default_logfile: PathBuf,
}

/// Parse a `-o KEY=VALUE` argument; the `o_lineno` counter for
/// stable cmdline ordering is owned by the caller.
fn parse_o_arg(v: &str, o_lineno: u32) -> Result<tinc_conf::Entry, String> {
    match parse_line(v, Source::Cmdline { line: o_lineno }) {
        None => Err(format!("-o requires KEY=VALUE, got `{v}'")),
        Some(Err(e)) => Err(format!("{e}")),
        Some(Ok(e)) => Ok(e),
    }
}

/// Parse `-d` / `-d N`. The lookahead is gated on `!starts_with('-')`
/// so `-d -D` does not eat the next flag; the NixOS module emits
/// `-d 0` as two argv entries which depends on this.
///
/// Increment is from 0 (first bare `-d` → 1) rather than C's
/// `-1`-init; differs only for `-d -d`, which folds into the same
/// `LevelFilter` bucket.
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
/// UTF-8.
fn next_str(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires an argument"))?
        .into_string()
        .map_err(|v| format!("{flag}: non-UTF-8 argument: {}", v.display()))
}

#[expect(clippy::too_many_lines)] // flat getopt-style match
fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut confbase: Option<PathBuf> = None;
    let mut netname: Option<String> = None;
    let mut pidfile = None;
    let mut socket = None;
    let mut cmdline_conf = Config::new();
    // 1-based ordinal for stable sort of multi-valued `-o` keys.
    let mut o_lineno: u32 = 0;

    let mut do_detach = true;
    let mut do_mlock = false;
    let mut allow_coredump = false;
    let mut switchuser = None;
    let mut do_chroot = false;
    let mut debug_level: Option<u32> = None;
    // Tri-state: None=not given, Some(None)=bare (derive post-loop),
    // Some(Some(p))=explicit. Collapsed to Option<PathBuf> below.
    let mut logfile: Option<Option<PathBuf>> = None;

    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(format!("non-UTF-8 argument: {}", arg.display()));
        };
        match arg {
            "-c" | "--config" => {
                confbase = Some(PathBuf::from(next_str(&mut args, "-c")?));
            }
            // Glued long/short forms (`--config=DIR`, `-cDIR`).
            // `getopt_long` accepts both; existing scripts (and the
            // NixOS tinc wrapper) use them.
            _ if arg.starts_with("--config=") => {
                confbase = Some(PathBuf::from(&arg["--config=".len()..]));
            }
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
            "-D" | "--no-detach" => {
                do_detach = false;
            }
            "-L" | "--mlock" => {
                do_mlock = true;
            }
            // No C equivalent. Dev opt-out for `harden_process`.
            "--allow-coredump" => {
                allow_coredump = true;
            }
            "-d" | "--debug" => {
                debug_level = Some(parse_debug_arg(debug_level, &mut args));
            }
            // Glued: `-d5` (atoi caps on overflow), `--debug=N`
            // (atoi-on-garbage matches C's 0).
            _ if arg.starts_with("-d") && arg[2..].chars().all(|c| c.is_ascii_digit()) => {
                let n: u32 = arg[2..].parse().unwrap_or(u32::MAX);
                debug_level = Some(n);
            }
            _ if arg.starts_with("--debug=") => {
                debug_level = Some(arg["--debug=".len()..].parse().unwrap_or(0));
            }
            // No syslog backend. Hard-error rather than warn so a
            // detaching `-s` unit file doesn't silently discard logs;
            // use `-D` under systemd (journald captures stderr).
            "-s" | "--syslog" => {
                return Err("-s/--syslog is not supported; use -D (journald \
                     captures stderr) or --logfile"
                    .into());
            }
            // Bare `--logfile` is valid (derive default post-loop).
            // Peek gated on `!starts_with('-')` so `--logfile -d 5`
            // doesn't eat `-d`.
            "--logfile" => {
                if let Some(next) = args.peek()
                    && let Some(s) = next.to_str()
                    && !s.starts_with('-')
                {
                    let v = args.next().unwrap();
                    logfile = Some(Some(PathBuf::from(v)));
                } else {
                    // Bare form; netname may be set by a later `-n`.
                    logfile = Some(None);
                }
            }
            _ if arg.starts_with("--logfile=") => {
                logfile = Some(Some(PathBuf::from(&arg["--logfile=".len()..])));
            }
            "-U" | "--user" => {
                switchuser = Some(next_str(&mut args, "-U")?);
            }
            _ if arg.starts_with("--user=") => {
                switchuser = Some(arg["--user=".len()..].to_owned());
            }
            _ if arg.starts_with("-U") && arg.len() > 2 => {
                switchuser = Some(arg[2..].to_owned());
            }
            "-R" | "--chroot" => {
                do_chroot = true;
            }
            // Parse the value as a config line; fail-fast on malformed.
            "-o" | "--option" => {
                let v = next_str(&mut args, "-o")?;
                o_lineno += 1;
                cmdline_conf.merge(std::iter::once(parse_o_arg(&v, o_lineno)?));
            }
            // Glued `--option=K=V` and `-oK=V` (the man page form).
            _ if arg.starts_with("--option=") => {
                o_lineno += 1;
                let v = &arg["--option=".len()..];
                cmdline_conf.merge(std::iter::once(parse_o_arg(v, o_lineno)?));
            }
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
                // stdout so `tincd --help | less` works.
                println!("Usage: tincd [option]...");
                println!();
                println!("  -c, --config=DIR        Read configuration from DIR.");
                println!("  -n, --net=NETNAME       Connect to net NETNAME.");
                println!("  -o, --option[=HOST.]K=V Set config option (repeatable).");
                println!("  -D, --no-detach         Don't fork and detach.");
                println!("  -d, --debug[=LEVEL]     Increase debug level or set to LEVEL.");
                println!("  -L, --mlock             Lock tinc into main memory.");
                println!("      --allow-coredump    Don't disable core dumps (debugging).");
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
                // "(Rust)" suffix disambiguates from the C build in bug reports.
                println!(
                    "tincd {} (Rust) protocol {}.{}",
                    env!("CARGO_PKG_VERSION"),
                    tinc_proto::request::PROT_MAJOR,
                    tinc_proto::request::PROT_MINOR,
                );
                std::process::exit(0);
            }
            // C accepts this; we don't implement it (would disable auth).
            // Warn rather than reject so old wiki/forum scripts produce
            // a clear message instead of "unknown argument".
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

    // NETNAME env fallback when `-n` not given.
    if netname.is_none()
        && let Ok(env_net) = std::env::var("NETNAME")
    {
        netname = Some(env_net);
    }

    // "." / empty mean "no netname, use confdir directly".
    if matches!(netname.as_deref(), Some("" | ".")) {
        netname = None;
    }

    // Path-traversal guard: netname becomes a path component, so
    // reject slashes and leading dot (would let `..` escape confdir).
    if let Some(net) = &netname
        && (net.starts_with('.') || net.contains('/') || net.contains('\\'))
    {
        return Err("Invalid character in netname!".into());
    }

    // make_names: -c wins over -n; warn on conflict (logger not up).
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

    // "tinc" or "tinc.NETNAME"; shared by logfile + pidfile.
    let identname = match &netname {
        Some(net) => format!("tinc.{net}"),
        None => "tinc".to_owned(),
    };

    // Default logfile derived now (netname is final), but the
    // detach-with-no-sink fallback that *uses* it lives in `main()`
    // — done after socket activation finalises `do_detach`, else a
    // socket-activated daemon's logs would divert from journald.
    let default_logfile: PathBuf = [LOCALSTATEDIR, "log", &format!("{identname}.log")]
        .iter()
        .collect();
    let logfile = logfile.map(|explicit| explicit.unwrap_or_else(|| default_logfile.clone()));

    // pidfile: /var/run/tinc.NET.pid when /var is writable, else
    // {confbase}/pid (the non-root fallback).
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
    // Derive `socket` from `pidfile` so callers (NixOS module,
    // `tinc -n NET`) can pass only --pidfile.
    let socket = socket.unwrap_or_else(|| {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let p = pidfile.as_os_str().as_bytes();
        let stem = p.strip_suffix(b".pid").unwrap_or(p);
        let mut s = Vec::with_capacity(stem.len() + 7);
        s.extend_from_slice(stem);
        s.extend_from_slice(b".socket");
        PathBuf::from(std::ffi::OsString::from_vec(s))
    });

    // Env alternative for wrappers that can't inject argv.
    if std::env::var_os("TINCR_ALLOW_COREDUMP").is_some() {
        allow_coredump = true;
    }

    Ok(Args {
        confbase,
        pidfile,
        socket,
        cmdline_conf,
        do_detach,
        do_mlock,
        allow_coredump,
        switchuser,
        do_chroot,
        debug_level,
        logfile,
        default_logfile,
    })
}

/// `tinc start` umbilical handshake: write a nul byte and close so
/// the spawning `tinc start` exits 0. We don't tee log output
/// through the umbilical (env_logger has no hook); the
/// detach-without-logfile warning in `init_logging` covers that gap.
/// No-op when `TINC_UMBILICAL` is unset.
fn cut_umbilical() {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    let Ok(spec) = std::env::var("TINC_UMBILICAL") else {
        return;
    };
    // First token is the fd; second (`colorize`) is ignored — we don't tee.
    let Some(fd) = spec
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<std::os::fd::RawFd>().ok())
    else {
        return;
    };
    // Reject stdio: taking ownership of 0/1/2 would close it and
    // let the next open() reuse the slot. `tinc start` always
    // passes a socketpair half (≥3).
    if fd <= 2 {
        log::warn!(target: "tincd",
            "TINC_UMBILICAL={spec}: fd {fd} is stdio/invalid, ignoring");
        return;
    }
    // SAFETY: fd > 2 checked above. The TINC_UMBILICAL env var is
    // the ownership transfer protocol — spawner set it, no one else
    // in this process knows the number. Stale fd → F_GETFL fails →
    // we drop (close) harmlessly.
    #[allow(unsafe_code)]
    let f = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    if fcntl(&f, FcntlArg::F_GETFL).is_err() {
        return; // drop closes the fd
    }
    let _ = fcntl(&f, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
    let _ = nix::unistd::write(&f, b"\0");
    // Drop closes. snip!
}

fn detach() -> Result<(), String> {
    // Single-threaded here (logger not yet initialised), so the
    // single-fork `daemon(3)` is safe; SIGPIPE is already SIG_IGN
    // via Rust's runtime, and USR1/USR2/WINCH get masked later in
    // `register_signals`.
    tincd::daemonize()
}

/// `getpwnam → initgroups → setgid → [chroot] → setuid`. chroot must
/// run after initgroups (which reads `/etc/group`, outside the jail)
/// and before setuid (chroot needs root); setuid is last so it can't
/// be undone.
fn drop_privs(
    switchuser: Option<&str>,
    do_chroot: bool,
    confbase: &std::path::Path,
) -> Result<(), String> {
    let uid_gid = if let Some(user) = switchuser {
        let pw = nix::unistd::User::from_name(user)
            .map_err(|e| format!("getpwnam_r `{user}': {e}"))?
            .ok_or_else(|| format!("unknown user `{user}'"))?;

        // initgroups: supplementary groups from /etc/group.
        // Single-threaded here (event loop not started).
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

    if do_chroot {
        // tzset before chroot: load /etc/localtime so log timestamps
        // stay in local tz inside the jail.
        // SAFETY: tzset is non-reentrant; single-threaded here.
        #[allow(unsafe_code)]
        {
            unsafe extern "C" {
                fn tzset();
            }
            unsafe { tzset() };
        }

        nix::unistd::chroot(confbase).map_err(|e| format!("System call `chroot' failed: {e}"))?;
        // Don't leave a cwd handle pointing outside the jail.
        std::env::set_current_dir("/").map_err(|e| format!("chdir / after chroot: {e}"))?;
    }

    // setresuid last (real/effective/saved); after this we can't undo.
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

    // PR_SET_NO_NEW_PRIVS: future execve can't grant setuid/file caps.
    // Set unconditionally; the sandbox path sets it again harmlessly.
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        log::warn!(target: "tincd", "prctl(PR_SET_NO_NEW_PRIVS): {e}");
    }

    Ok(())
}

/// `ProcessPriority` config key. Best-effort: a daemon that can't
/// nice itself can still tunnel packets. Re-reads tinc.conf rather
/// than threading the merged config out of `Daemon::setup`.
fn apply_process_priority(confbase: &std::path::Path, cmdline: &Config) {
    let mut config = match tinc_conf::read_server_config(confbase) {
        Ok(c) => c,
        // Daemon::setup already validated this read; failure here is
        // a race. Priority is a hint, skip.
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

    // Unix nice mapping of C's Windows priority-class names.
    let nice: i32 = match prio_str.to_ascii_lowercase().as_str() {
        "normal" => 0,
        "low" => 10,
        "high" => -10,
        other => {
            log::error!(target: "tincd", "Invalid priority `{other}`!");
            return;
        }
    };

    // SAFETY: setpriority(PRIO_PROCESS, 0, nice); who=0 = current process.
    // PRIO_PROCESS type varies (c_uint on gnu, c_int on musl/bsd) —
    // rely on the libc const's own type via `as _`.
    #[allow(unsafe_code)]
    let r = unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, nice) };
    if r != 0 {
        log::warn!(
            target: "tincd",
            "System call `setpriority' failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Precedence: `RUST_LOG` > `-d` > default Info. `LogLevel` from
/// `-o`/tinc.conf is already folded into `args.debug_level` by
/// [`resolve_debug_level`].
fn init_logging(args: &Args) {
    // Global `info`, not `tincd=info`: dependent crates' warn/error
    // (tinc-sptps decrypt failures, tinc-device ioctl errors) must
    // surface at default verbosity.
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

    // RUST_LOG (target-scoped) wins over filter_level (global floor).
    if let Some(d) = args.debug_level {
        builder.filter_level(debug_level_to_filter(d));
    }

    if let Some(path) = &args.logfile {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)
        {
            Ok(f) => {
                builder.target(env_logger::Target::Pipe(Box::new(f)));
            }
            Err(e) => {
                // Logger not init'd — fall through to stderr.
                eprintln!("tincd: --logfile {}: {e}", path.display());
            }
        }
    }

    // log_tap wraps env_logger so REQ_LOG control conns can tee.
    let inner = builder.build();
    tincd::log_tap::init(inner);

    // Seed log_tap's debug-level atomic for REQ_SET_DEBUG replies.
    // `init_*`, not `set_*`: the latter would clobber the level
    // env_logger just installed from RUST_LOG.
    #[expect(clippy::cast_possible_wrap)] // debug_level is 0..=5 (CLI-validated)
    tincd::log_tap::init_debug_level(args.debug_level.map_or(0, |d| d as i32));
}

/// Precedence (first hit wins): `-d` argv > `-o LogLevel=N` >
/// `LogLevel` in tinc.conf > None (caller defaults to Info).
///
/// Re-reads tinc.conf (~1KB) here rather than reordering logger
/// init after `Daemon::setup`. Negative `LogLevel` rejected via
/// `u32::try_from` (stricter than C's atoi).
fn resolve_debug_level(args: &Args) -> Option<u32> {
    fn lookup(c: &Config) -> Option<u32> {
        c.lookup("LogLevel")
            .next()
            .and_then(|e| e.get_int().ok())
            .and_then(|v| u32::try_from(v).ok())
    }

    if args.debug_level.is_some() {
        return args.debug_level;
    }
    if let Some(v) = lookup(&args.cmdline_conf) {
        return Some(v);
    }
    // Read failure → silent None; logger isn't up to report it and
    // Daemon::setup will surface the real error.
    tinc_conf::read_server_config(&args.confbase)
        .ok()
        .and_then(|c| lookup(&c))
}

/// `Sandbox` config key; `-o` overrides tinc.conf. Default `none`
/// (Landlock is always compiled in but unconfigured daemons keep
/// pre-sandbox behaviour).
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
    // Read failure silent; Daemon::setup reports it.
    if let Ok(c) = tinc_conf::read_server_config(confbase)
        && let Some(r) = lookup(&c)
    {
        return r;
    }
    Ok(sandbox::Level::None)
}

/// systemd socket activation env-var parse.
///
/// The `LISTEN_PID == getpid()` check is the security gate: a stale
/// `LISTEN_FDS=N` inherited from a wrapper would otherwise make us
/// adopt fds 3..N+3 as listen sockets when they're actually log
/// files / pipes / garbage.
///
/// Returns `Some(n)` only when both PID matches and `LISTEN_FDS` is
/// a positive count. Env values are passed in (rather than read
/// here) so tests can avoid `unsafe { set_var }`.
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

/// Disable core dumps before any key load: a core file would leak
/// the Ed25519 private key and every live SPTPS key. `RLIMIT_CORE=0`
/// covers on-disk dumps; Linux `PR_SET_DUMPABLE=0` additionally
/// blocks same-uid ptrace and systemd-coredump pipe handlers (which
/// ignore RLIMIT_CORE).
fn harden_process(allow_coredump: bool) {
    if allow_coredump {
        return;
    }
    if let Err(e) = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0) {
        // pre-init_logging → eprintln
        eprintln!("tincd: setrlimit(RLIMIT_CORE, 0): {e} (continuing)");
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        eprintln!("tincd: prctl(PR_SET_DUMPABLE, 0): {e} (continuing)");
    }
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

    // Disable coredumps before any key load (Daemon::setup below).
    harden_process(args.allow_coredump);

    // chdir confbase BEFORE detach: `daemon(3)`'s nochdir=1 carries
    // the cwd across fork, and tinc-up / tinc-down / host-* scripts
    // rely on cwd == confbase to resolve `hosts/$NODE`. The chroot
    // path overrides cwd to "/" in drop_privs, which still resolves
    // inside the jail.
    if let Err(e) = std::env::set_current_dir(&args.confbase) {
        eprintln!(
            "Could not change to configuration directory {}: {e}",
            args.confbase.display()
        );
        return ExitCode::FAILURE;
    }

    // Socket activation BEFORE detach: a forked child has a new PID
    // so LISTEN_PID would no longer match — we'd lose the inherited
    // fds. So clear `do_detach` here when activated.
    let socket_activation = check_socket_activation(
        std::env::var("LISTEN_PID").ok(),
        std::env::var("LISTEN_FDS").ok(),
    );
    // SAFETY: single-threaded pre-detach, no concurrent getenv.
    #[allow(unsafe_code)]
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
    }
    if socket_activation.is_some() {
        args.do_detach = false;
    }

    // Detach + no `--logfile` would leave us mute (stderr →
    // /dev/null); derive a default. Done after socket activation so
    // an activated daemon keeps logging to stderr → journald.
    if args.do_detach && args.logfile.is_none() {
        eprintln!(
            "tincd: detaching without --logfile; writing logs to {}",
            args.default_logfile.display()
        );
        args.logfile = Some(args.default_logfile.clone());
    }

    // detach BEFORE logger init: avoid fds/threads crossing the fork.
    if args.do_detach
        && let Err(e) = detach()
    {
        eprintln!("tincd: {e}");
        return ExitCode::FAILURE;
    }

    // Fold tinc.conf LogLevel into args.debug_level before logger
    // init so init_debug_level seeds REQ_SET_DEBUG with it too.
    args.debug_level = resolve_debug_level(&args);

    init_logging(&args);

    // No build date — reproducible builds.
    log::info!(
        target: "tincd",
        "tincd {} starting, debug level {}",
        env!("CARGO_PKG_VERSION"),
        args.debug_level.unwrap_or(0)
    );

    // mlockall after fork (parent is short-lived). Hard-fail on
    // EPERM: if `-L` was requested without CAP_IPC_LOCK, key pages
    // could swap — the user wants to know.
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

    // ProcessPriority before setup: covers TUN open and tinc-up,
    // and the control socket appearing implies priority applied
    // (tests sync on that). Before drop_privs: negative nice needs
    // root or CAP_SYS_NICE.
    apply_process_priority(&args.confbase, &args.cmdline_conf);

    // setup_network opens TUN, binds sockets, runs tinc-up. All
    // need root; drop_privs is after.
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

    // tinc-down (Daemon::Drop) inherits the post-drop_privs uid:
    // it can't `ip link set down`. Known C limitation we share.
    if let Err(e) = drop_privs(args.switchuser.as_deref(), args.do_chroot, &args.confbase) {
        log::error!(target: "tincd", "{e}");
        // Hard exit: don't unwind Daemon::Drop with privs in an
        // unknown state.
        std::process::exit(1);
    }

    // sandbox after drop_privs. The Linux device path is hard-coded
    // /dev/net/tun (re-open mid-run is theoretical; upstream unveils
    // it, we match); dummy/fd device types pass None.
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

    // READY=1 gates dependent systemd units on a packet-forwarding
    // daemon, not just a started process.
    sd_notify::notify_ready();

    // `tinc start` blocks reading the umbilical fd; nul byte +
    // close lets it exit 0. No-op outside the `tinc start` path.
    cut_umbilical();

    // WATCHDOG pings come from `TimerWhat::Watchdog` inside the
    // event loop, so a wedged loop stops pinging and systemd
    // actually restarts us — a detached pinger would defeat that.

    // catch_unwind so a panic in the hot path (slotmap invariant
    // expects, poisoned mutexes) still routes through STOPPING=1.
    // Daemon::Drop (tinc-down, pidfile/socket unlink) already ran
    // during the unwind; this just adds the systemd notify + log.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| daemon.run()))
        .unwrap_or_else(|payload| {
            let msg = payload
                .downcast_ref::<&'static str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic payload>");
            log::error!(target: "tincd", "Panic in event loop: {msg}");
            RunOutcome::PollError
        });

    // STOPPING=1 extends systemd's stop timeout for tinc-down +
    // Daemon::Drop cleanup.
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
    fn default_logfile_derived_from_netname() {
        // The detach-with-no-sink fallback in main() uses this; it
        // must reflect the FINAL netname (here set after the option
        // that would consume it).
        let a = parse_args(argv(&["-n", "foo", "--pidfile=/tmp/p"])).unwrap();
        assert!(a.default_logfile.ends_with("log/tinc.foo.log"));
        // parse_args itself does NOT apply the fallback (that would
        // pre-empt the socket-activation foreground decision in
        // main()); logfile stays None until main() decides.
        assert_eq!(a.logfile, None);
    }

    #[test]
    fn syslog_flag_hard_errors() {
        // Warn-and-continue would silently discard logs from a
        // detached daemon; fail loudly so the unit file gets fixed.
        let Err(e) = parse_args(argv(&["-s", "-c", "/tmp", "--pidfile=/tmp/p"])) else {
            panic!("expected -s to be rejected");
        };
        assert!(e.contains("--syslog"), "got: {e}");
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
