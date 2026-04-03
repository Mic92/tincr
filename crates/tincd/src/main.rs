//! tincd binary entry point. Ports `tincd.c::main` (`tincd.c:464-
//! 735`, ~270 LOC) heavily abridged.
//!
//! ## What's here vs C `main()`
//!
//! C `main()` does:
//!
//! 1. `parse_options(argc, argv)` — getopt for `-c`, `-n`, `-d`,
//!    `--pidfile`, `--logfile`, `-L` (mlock), `-R` (chroot), `-U`
//!    (setuid), `-o` (cmdline config).
//! 2. `make_names(true)` — resolve confbase/pidfile/socket paths.
//! 3. `chdir(confbase)`.
//! 4. Open logger (stderr or file or syslog).
//! 5. Read config (`read_server_config`).
//! 6. `detach()` — daemonize.
//! 7. `setup_network()`.
//! 8. `drop_privs()`.
//! 9. `try_outgoing_connections()`.
//! 10. `main_loop()`.
//! 11. `close_network_connections()`.
//!
//! Skeleton: 1 (just `-c`, `--pidfile`, `--socket`), 4 (env_logger
//! to stderr), 7 (Daemon::setup), 10 (Daemon::run). The rest is
//! noted-and-skipped.
//!
//! ## Argv parsing: hand-rolled, not clap
//!
//! tinc-tools uses hand-rolled argv parsing (see `bin/tinc.rs`). Same
//! here. clap is +30 deps; tincd has 4 flags. The `parse_args`
//! function is 30 lines.
//!
//! `--pidfile` and `--socket` are explicit args (not derived from
//! confbase) because the integration test needs to point them at a
//! tempdir without the `/var/run` resolution dance. C tincd has
//! `--pidfile` but NOT `--socket` (it derives `.socket` from `.pid`).
//! We add `--socket` for testability. Chunk 3 can drop it once proper
//! `make_names(true)` lands.
//!
//! ## SIGPIPE
//!
//! `tinc-tools/bin/tinc.rs` resets SIGPIPE to default so `tinc dump |
//! head` exits cleanly. The daemon WANTS the opposite: SIGPIPE on a
//! send() to a closed control conn should NOT kill the daemon. Rust's
//! default is SIG_IGN (good); the C tincd doesn't touch SIGPIPE
//! (relies on `send()` returning EPIPE with the signal masked by the
//! TCP stack). We're fine with the Rust default. NO action needed.

use std::path::PathBuf;
use std::process::ExitCode;

use tincd::{Daemon, RunOutcome};

/// Parsed argv. The skeleton's flag set.
struct Args {
    /// `-c DIR`. Required (skeleton doesn't have `make_names`
    /// resolution).
    confbase: PathBuf,
    /// `--pidfile FILE`. Required.
    pidfile: PathBuf,
    /// `--socket FILE`. Required (testability hack; C derives this).
    socket: PathBuf,
}

/// Hand-rolled argv parsing. Same shape as `tinc-tools/bin/tinc.rs`.
fn parse_args() -> Result<Args, String> {
    let mut confbase = None;
    let mut pidfile = None;
    let mut socket = None;

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        // OsString → str. The flag names are ASCII; if argv has
        // non-UTF-8 in the flag itself (not the value), something
        // is very wrong.
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
                // C `usage(false)`. Minimal.
                eprintln!("Usage: tincd -c DIR --pidfile FILE --socket FILE");
                eprintln!("  Walking-skeleton daemon. Serves REQ_STOP only.");
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

    Ok(Args {
        confbase: confbase.ok_or("missing -c <confbase>")?,
        pidfile: pidfile.ok_or("missing --pidfile <path>")?,
        socket: socket.ok_or("missing --socket <path>")?,
    })
}

fn main() -> ExitCode {
    // ─── logger init
    // env_logger reads RUST_LOG. `RUST_LOG=tincd` for everything;
    // `RUST_LOG=tincd::meta=debug` for the C `-d4` equivalent.
    // Default level Info (matches C `DEBUG_NOTHING` which still
    // prints "Ready" and "Terminating").
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("tincd=info"))
        .init();

    // ─── argv
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tincd: {e}");
            eprintln!("Try `tincd --help` for usage.");
            return ExitCode::FAILURE;
        }
    };

    // ─── setup
    // C `tincd.c:665` `setup_network()`. Daemon::setup is the bulk
    // of it (the heavily-abridged version).
    let daemon = match Daemon::setup(&args.confbase, &args.pidfile, &args.socket) {
        Ok(d) => d,
        Err(e) => {
            log::error!(target: "tincd", "Setup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // ─── run
    // C `tincd.c:717` `status = main_loop()`. The loop runs until
    // `running = false` (REQ_STOP, SIGTERM, etc).
    //
    // C steps NOT here (chunk 3+):
    //   - detach() (daemonize)
    //   - drop_privs() (setuid)
    //   - try_outgoing_connections()
    //   - the umbilical write (TINC_UMBILICAL fd from `tinc start`)
    match daemon.run() {
        RunOutcome::Clean => ExitCode::SUCCESS,
        RunOutcome::PollError => ExitCode::FAILURE,
    }
    // Daemon dropped here: pidfile unlinked, control socket unlinked.
}
