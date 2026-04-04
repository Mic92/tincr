//! tincd binary entry point. Ports `tincd.c::main` (`tincd.c:464-735`).
//!
//! Hand-rolled argv (no clap; ~6 flags). `--socket` is a testability
//! addition (C derives it from `--pidfile`). Not yet ported: detach,
//! drop_privs, umbilical.
//!
//! ## `-n` / `-o` (this commit)
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

use std::path::PathBuf;
use std::process::ExitCode;

use tinc_conf::{Config, Source, parse_line};
use tincd::{Daemon, RunOutcome};

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

struct Args {
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    /// Parsed `-o` entries, `Source::Cmdline`-tagged. Passed through
    /// to `Daemon::setup`. Empty when no `-o` given; setup() merges
    /// an empty Config (no-op) — simpler than `Option<Config>`.
    cmdline_conf: Config,
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

    // C `tincd.c:717` main_loop()
    match daemon.run() {
        RunOutcome::Clean => ExitCode::SUCCESS,
        RunOutcome::PollError => ExitCode::FAILURE,
    }
}
