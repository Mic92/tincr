//! tincd binary entry point. Ports `tincd.c::main` (`tincd.c:464-735`).
//!
//! Hand-rolled argv (no clap; 4 flags). `--socket` is a testability
//! addition (C derives it from `--pidfile`). Not yet ported: detach,
//! drop_privs, make_names, umbilical.

use std::path::PathBuf;
use std::process::ExitCode;

use tincd::{Daemon, RunOutcome};

struct Args {
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut confbase = None;
    let mut pidfile = None;
    let mut socket = None;

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
    // Default level Info ≈ C `DEBUG_NOTHING` (still prints "Ready"/"Terminating").
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("tincd=info"))
        .init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tincd: {e}");
            eprintln!("Try `tincd --help` for usage.");
            return ExitCode::FAILURE;
        }
    };

    // C `tincd.c:665` setup_network()
    let daemon = match Daemon::setup(&args.confbase, &args.pidfile, &args.socket) {
        Ok(d) => d,
        Err(e) => {
            log::error!(target: "tincd", "Setup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // C `tincd.c:717` main_loop()
    match daemon.run() {
        RunOutcome::Clean => ExitCode::SUCCESS,
        RunOutcome::PollError => ExitCode::FAILURE,
    }
}
