//! argv parsing and the config-derived paths/log level.

use nix::unistd::{AccessFlags, access};
use std::ffi::OsString;
use std::iter::Peekable;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::{env, iter, process};
use tinc_conf::{Config, Source, parse_line};

const CONFDIR: &str = match option_env!("TINC_CONFDIR") {
    Some(d) => d,
    None => "/etc",
};

/// Default base for pidfile/logfile; override via `TINC_LOCALSTATEDIR`.
const LOCALSTATEDIR: &str = match option_env!("TINC_LOCALSTATEDIR") {
    Some(d) => d,
    None => "/var",
};

/// Map C debug levels (0=NOTHING through 5=TRAFFIC) onto Rust's
/// 3-level filter. `target: "tincd"` filtering via `RUST_LOG`
/// recovers finer granularity.
pub(crate) const fn debug_level_to_filter(d: u32) -> log::LevelFilter {
    match d {
        0 => log::LevelFilter::Info,
        1 | 2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

#[expect(clippy::struct_excessive_bools)] // independent CLI switches
pub(crate) struct Args {
    pub confbase: PathBuf,
    pub pidfile: PathBuf,
    pub socket: PathBuf,
    /// `-o` entries, `Source::Cmdline`-tagged. Empty when none given.
    pub cmdline_conf: Config,

    /// `-D` clears (default true).
    pub do_detach: bool,
    /// `-L`.
    pub do_mlock: bool,
    /// `--allow-coredump` / `TINCR_ALLOW_COREDUMP=1`. Opts out of
    /// [`harden_process`] so `coredumpctl gdb` works.
    pub allow_coredump: bool,
    /// `-U USER`. None → don't drop.
    pub switchuser: Option<String>,
    /// `-R`. Applied inside `drop_privs` between setgid and setuid.
    pub do_chroot: bool,
    /// `-d` / `--debug`. None means "not given" — distinct from 0,
    /// because the `LogLevel` tinc.conf fallback only fires when
    /// `-d` was absent. `RUST_LOG` still wins over both.
    pub debug_level: Option<u32>,
    /// `--logfile [PATH]`; bare form derives
    /// `LOCALSTATEDIR/log/tinc.NETNAME.log` post-loop.
    pub logfile: Option<PathBuf>,
    /// Default sink for the detach-with-no-`--logfile` fallback.
    /// Applied in `main()` after socket activation has finalised
    /// `do_detach`, not in `parse_args`.
    pub default_logfile: PathBuf,
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
fn parse_debug_arg<I>(current: Option<u32>, args: &mut Peekable<I>) -> u32
where
    I: Iterator<Item = OsString>,
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
fn next_str(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires an argument"))?
        .into_string()
        .map_err(|v| format!("{flag}: non-UTF-8 argument: {}", v.display()))
}

#[expect(clippy::too_many_lines)] // flat getopt-style match
pub(crate) fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = OsString>,
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
                cmdline_conf.merge(iter::once(parse_o_arg(&v, o_lineno)?));
            }
            // Glued `--option=K=V` and `-oK=V` (the man page form).
            _ if arg.starts_with("--option=") => {
                o_lineno += 1;
                let v = &arg["--option=".len()..];
                cmdline_conf.merge(iter::once(parse_o_arg(v, o_lineno)?));
            }
            _ if arg.starts_with("-o") && arg.len() > 2 => {
                o_lineno += 1;
                cmdline_conf.merge(iter::once(parse_o_arg(&arg[2..], o_lineno)?));
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
                process::exit(0);
            }
            "--version" => {
                // "(Rust)" suffix disambiguates from the C build in bug reports.
                println!(
                    "tincd {} (Rust) protocol {}.{}",
                    env!("CARGO_PKG_VERSION"),
                    tinc_proto::request::PROT_MAJOR,
                    tinc_proto::request::PROT_MINOR,
                );
                process::exit(0);
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
        && let Ok(env_net) = env::var("NETNAME")
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
        let p = pidfile.as_os_str().as_bytes();
        let stem = p.strip_suffix(b".pid").unwrap_or(p);
        let mut s = Vec::with_capacity(stem.len() + 7);
        s.extend_from_slice(stem);
        s.extend_from_slice(b".socket");
        PathBuf::from(OsString::from_vec(s))
    });

    // Env alternative for wrappers that can't inject argv.
    if env::var_os("TINCR_ALLOW_COREDUMP").is_some() {
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

/// Precedence (first hit wins): `-d` argv > `-o LogLevel=N` >
/// `LogLevel` in tinc.conf > None (caller defaults to Info).
///
/// Re-reads tinc.conf (~1KB) here rather than reordering logger
/// init after `Daemon::setup`. Negative `LogLevel` rejected via
/// `u32::try_from` (stricter than C's atoi).
pub(crate) fn resolve_debug_level(args: &Args) -> Option<u32> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::ffi::OsString;
    use std::fs;

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
        // parse_args itself does not apply the fallback (that would
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

    // resolve_debug_level.

    // Hand-rolled tempdir (matches tests/common/mod.rs::TmpGuard;
    // no tempfile dep in this crate). PID+TID → nextest-parallel-safe.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let d = env::temp_dir().join(format!(
                "tincd-loglevel-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Self(d)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
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
        fs::write(t.0.join("tinc.conf"), "LogLevel = 3\n").unwrap();
        let mut a = args_at(t.0.clone());
        a.debug_level = Some(5);
        assert_eq!(resolve_debug_level(&a), Some(5));
    }

    #[test]
    fn loglevel_from_cmdline_o() {
        // No tinc.conf on disk → if this passes, we know -o was
        // checked before the file (and the file read short-circuited).
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
        fs::write(t.0.join("tinc.conf"), "LogLevel = 4\n").unwrap();
        let a = args_at(t.0.clone());
        assert_eq!(resolve_debug_level(&a), Some(4));
    }

    #[test]
    fn loglevel_absent_everywhere() {
        let t = Tmp::new("absent");
        fs::write(t.0.join("tinc.conf"), "Name = foo\n").unwrap();
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
        fs::write(t.0.join("tinc.conf"), "LogLevel = -2\n").unwrap();
        let a = args_at(t.0.clone());
        assert_eq!(resolve_debug_level(&a), None);
    }
}
