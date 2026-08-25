//! tincd binary entry point.
//!
//! Boot ordering (same as C tincd, tinc-up needs root):
//!     detach → mlockall → `setup_network` (binds + tinc-up as root)
//!     → `ProcessPriority` → `drop_privs` → `main_loop`.
//!
//! `-D` (no-detach) is required for the test suite; `tests/common/
//! mod.rs::tincd_cmd()` sets it. `-n NETNAME` (or `NETNAME` env)
//! derives confbase as `CONFDIR/tinc/NETNAME`. `-o KEY=VALUE` is
//! parsed via `tinc-conf::parse_line` and merged with `Source::
//! Cmdline` so it beats file values.

// New unsafe in the entrypoint should trip the lint; remaining
// per-site uses carry an explicit `#[expect(unsafe_code)]`.
#![deny(unsafe_code)]

mod args;
mod procsetup;

use args::{Args, debug_level_to_filter, parse_args, resolve_debug_level};
use nix::sys::mman::{MlockAllFlags, mlockall};
use procsetup::{
    apply_process_priority, check_socket_activation, cut_umbilical, detach, drop_privs,
    harden_process, resolve_sandbox_level,
};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::panic::AssertUnwindSafe;
use std::process::ExitCode;
use std::{env, panic, process};
use tincd::{Daemon, RunOutcome, sandbox, sd_notify};

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
        match OpenOptions::new()
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

fn main() -> ExitCode {
    let mut args = match parse_args(env::args_os().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tincd: {e}");
            eprintln!("Try `tincd --help` for usage.");
            return ExitCode::FAILURE;
        }
    };

    // Disable coredumps before any key load (Daemon::setup below).
    harden_process(args.allow_coredump);

    // chdir confbase before detach: `daemon(3)`'s nochdir=1 carries
    // the cwd across fork, and tinc-up / tinc-down / host-* scripts
    // rely on cwd == confbase to resolve `hosts/$NODE`. The chroot
    // path overrides cwd to "/" in drop_privs, which still resolves
    // inside the jail.
    if let Err(e) = env::set_current_dir(&args.confbase) {
        eprintln!(
            "Could not change to configuration directory {}: {e}",
            args.confbase.display()
        );
        return ExitCode::FAILURE;
    }

    // Socket activation before detach: a forked child has a new PID
    // so LISTEN_PID would no longer match — we'd lose the inherited
    // fds. So clear `do_detach` here when activated.
    let socket_activation =
        check_socket_activation(env::var("LISTEN_PID").ok(), env::var("LISTEN_FDS").ok());
    // SAFETY: single-threaded pre-detach, no concurrent getenv.
    #[expect(unsafe_code)]
    unsafe {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
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

    // detach before logger init: avoid fds/threads crossing the fork.
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
    if args.do_mlock
        && let Err(e) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)
    {
        log::error!(target: "tincd", "System call `mlockall' failed: {e}");
        return ExitCode::FAILURE;
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
        process::exit(1);
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
        #[cfg(any(target_os = "linux", target_os = "android"))]
        device: Some("/dev/net/tun".into()),
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
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
    let outcome =
        panic::catch_unwind(AssertUnwindSafe(|| daemon.run())).unwrap_or_else(|payload| {
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
