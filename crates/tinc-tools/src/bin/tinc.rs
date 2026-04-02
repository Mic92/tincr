//! The `tinc` CLI binary. C reference: `tincctl.c`.
//!
//! ## Current scope: Phase 4a filesystem-only commands
//!
//! Just `init` for now. The dispatch table (`COMMANDS`) is the same
//! shape as `tincctl.c:3000-3050`'s `commands[]` array; adding a
//! command is one entry + one module in `cmd/`. The argv parsing and
//! `Paths` resolution are done once, here, and every command gets them
//! pre-chewed.
//!
//! ## Why hand-rolled getopt, not `clap`
//!
//! Same call as `sptps_test`: 4 global options (`-c`, `-n`, `--help`,
//! `--version`) + a subcommand name + per-subcommand positionals.
//! `clap` would handle this beautifully but pulls in ~40 transitive
//! deps and the proc-macro compilation hit. The hand-rolled version
//! below is ~80 lines and matches getopt's behavior closely enough
//! that `tinc -n foo init bar` and `tinc init -n foo bar` and
//! `NETNAME=foo tinc init bar` all work the same as the C.
//!
//! Well — almost. C's `getopt_long` with `"+bc:n:"` (the `+` means
//! "stop at first non-option") only accepts global options *before*
//! the subcommand. We do the same: `tinc init -n foo bar` would treat
//! `-n` as a positional for `init`. That's the C behavior (`+` mode).
//! It's also what users expect from `git`-style CLIs (`git -C dir
//! commit` not `git commit -C dir`).
//!
//! ## Exit codes
//!
//! C `tincctl.c` returns 1 on any error. So do we. There's no
//! granular exit code tradition to preserve.

// Silence pedantic lints that fight CLI binary patterns. Same set as
// sptps_test, same reasoning.
#![allow(clippy::doc_markdown)]
#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_tools::cmd::{self, CmdError};
use tinc_tools::names::{Paths, PathsInput};

/// One row of the dispatch table. Name, handler, one-line help.
struct CmdEntry {
    name: &'static str,
    /// Positional args after the subcommand name. The handler does its
    /// own arity checking — `init` wants exactly one, `export` wants
    /// zero, etc. Passing `&[String]` instead of typed args keeps the
    /// table uniform; commands that want types parse inside.
    run: fn(&Paths, &[String]) -> Result<(), CmdError>,
    help: &'static str,
}

/// `tincctl.c:3000` `static const struct { ... } commands[]`.
///
/// The C table has a `bool ctl` flag for "needs daemon connection".
/// We don't — daemon-RPC commands aren't here yet (Phase 5b), and when
/// they are, they'll go in a separate table because the function
/// signature differs (they take a `&mut CtlSocket`, not `&Paths`).
/// One table per dispatch shape, not one table with a union of shapes.
const COMMANDS: &[CmdEntry] = &[
    CmdEntry {
        name: "init",
        run: cmd_init,
        help: "init NAME              Create initial configuration files.",
    },
    // More 4a commands land here: generate-keys, export, import, fsck, sign, verify.
    // 5b commands (dump, top, log, ...) go in a separate table.
];

/// Thin adapter: `&[String]` argv → typed args for `cmd::init::run`.
/// Each command has one of these; it's where arity errors live.
///
/// C `cmd_init` does `if(argc > 2)` / `if(argc < 2)` inline. We do it
/// here so `cmd::init::run` gets a nice `&str` and never sees argv.
fn cmd_init(paths: &Paths, args: &[String]) -> Result<(), CmdError> {
    match args {
        [] => Err(CmdError::MissingArg("Name")),
        [name] => cmd::init::run(paths, name),
        [_, _, ..] => Err(CmdError::TooManyArgs),
    }
}

// ────────────────────────────────────────────────────────────────────

/// `parse_options` + the env-var fallback. C: `tincctl.c:207-278`.
///
/// Returns the resolved `PathsInput` and the leftover argv (the
/// subcommand name plus its positionals). The leftover is `Vec<String>`
/// not `&[String]` because we consume the iterator; the caller indexes
/// it once.
///
/// `Err(String)` is the message to print before exiting nonzero.
fn parse_global_options(
    mut args: impl Iterator<Item = String>,
) -> Result<(PathsInput, Vec<String>), String> {
    let mut input = PathsInput::default();
    let mut rest = Vec::new();

    // C `getopt_long(argc, argv, "+bc:n:", ...)` — the `+` means stop
    // at first non-option. We loop until we hit something that doesn't
    // start with `-`, then dump everything remaining into `rest`.
    //
    // No bundled short flags here (`-cn` doesn't mean `-c -n`) because
    // both `-c` and `-n` take arguments. Short-with-arg can be `-cFOO`
    // or `-c FOO` in getopt; we only support the spaced form. The C
    // accepts both (getopt does); nobody uses the squished form for
    // path arguments, and supporting it correctly is fiddly (`-c-n`
    // — is that `-c` with arg `-n`, or two flags?). Not worth it.
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let val = args.next().ok_or("option -c requires an argument")?;
                input.confbase = Some(PathBuf::from(val));
            }
            // `--config=DIR` glued form. getopt_long handles this; we
            // do too because it's the form people copy-paste from
            // systemd unit files.
            s if s.starts_with("--config=") => {
                input.confbase = Some(PathBuf::from(&s["--config=".len()..]));
            }
            "-n" | "--net" => {
                let val = args.next().ok_or("option -n requires an argument")?;
                input.netname = Some(val);
            }
            s if s.starts_with("--net=") => {
                input.netname = Some(s["--net=".len()..].to_owned());
            }
            "--help" => {
                // C sets a flag, prints help in main, returns 0. We
                // short-circuit by returning a sentinel rest vec —
                // ugly but avoids a third Result variant. The caller
                // checks for this.
                rest.push("--help".into());
                return Ok((input, rest));
            }
            "--version" => {
                rest.push("--version".into());
                return Ok((input, rest));
            }
            // C `OPT_BATCH` sets `tty = false` — disables interactive
            // prompts. We have no prompts (see `cmd/init.rs` doc), so
            // -b is a no-op. Accept-and-ignore for compat with scripts
            // that pass it.
            "-b" | "--batch" => {}
            // Unknown option. C: `usage(true); return false`.
            s if s.starts_with('-') => {
                return Err(format!("unknown option: {s}"));
            }
            // First non-option: subcommand name. Everything after is
            // positional, even if it starts with `-` (getopt `+` mode).
            // This means `tinc init --weird-name` would try to use
            // `--weird-name` as a node name and fail check_id. Correct.
            _ => {
                rest.push(arg);
                rest.extend(args);
                break;
            }
        }
    }

    // ─── NETNAME env fallback ───────────────────────────────────────
    // C: `tincctl.c:258-263`. Only if -n wasn't given. Standard
    // env-under-flag precedence.
    if input.netname.is_none() {
        if let Ok(env_net) = env::var("NETNAME") {
            input.netname = Some(env_net);
        }
    }

    // ─── netname "." → None ─────────────────────────────────────────
    // C: `tincctl.c:267-270`. "." is the "top-level" sentinel — it
    // means "no netname, use confdir as confbase". Allows `NETNAME=.`
    // in your env to explicitly say "I want /etc/tinc not
    // /etc/tinc/$NETNAME". Also the empty string (which you can't
    // pass with `-n` but can set in env: `NETNAME=`).
    if matches!(input.netname.as_deref(), Some("" | ".")) {
        input.netname = None;
    }

    // ─── netname path-traversal guard ───────────────────────────────
    // C: `tincctl.c:272-276` `strpbrk(netname, "\\/") || *netname == '.'`.
    // Netname becomes a path component; slashes would escape confdir.
    // Leading dot rejects `..` (`strpbrk` doesn't catch `..` but `*=='.'`
    // does — and also rejects `.hidden`, which is fine, nobody names
    // their VPN `.git`).
    //
    // This is a *weaker* check than `check_id` — netname allows `-`,
    // for instance. The C is permissive here on purpose; netname is a
    // local filesystem thing, not a wire protocol token.
    if let Some(net) = &input.netname {
        if net.starts_with('.') || net.contains('/') || net.contains('\\') {
            return Err("Invalid character in netname!".into());
        }
    }

    Ok((input, rest))
}

fn print_help() {
    // The C help text is ~40 lines covering every command. We only
    // have one. Generate from COMMANDS so adding an entry adds it to
    // help automatically.
    println!("Usage: tinc [OPTION]... COMMAND [ARGS]...");
    println!();
    println!("Options:");
    println!("  -c, --config=DIR    Read configuration from DIR.");
    println!("  -n, --net=NETNAME   Connect to net NETNAME.");
    println!("  -b, --batch         Don't ask for anything (no-op; we never prompt).");
    println!("      --help          Display this help and exit.");
    println!("      --version       Output version information and exit.");
    println!();
    println!("Commands:");
    for c in COMMANDS {
        println!("  {}", c.help);
    }
    println!();
    println!("Phase 4a build — filesystem commands only. Daemon RPC");
    println!("commands (dump, top, log, ...) land with the daemon in");
    println!("Phase 5b. See RUST_REWRITE_PLAN.md.");
}

fn print_version() {
    // C prints the meson-baked version string + a copyright blurb. We
    // use Cargo's. The "(Rust)" suffix is so `tinc --version` in a
    // bug report tells you immediately which binary you're running.
    println!("tinc {} (Rust)", env!("CARGO_PKG_VERSION"));
}

fn main() -> ExitCode {
    // Skip argv[0].
    let args = env::args().skip(1);

    let (input, rest) = match parse_global_options(args) {
        Ok(x) => x,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("Try `tinc --help' for more information.");
            return ExitCode::FAILURE;
        }
    };

    // The --help/--version short-circuits from parse_global_options.
    match rest.first().map(String::as_str) {
        Some("--help") => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some("--version") => {
            print_version();
            return ExitCode::SUCCESS;
        }
        None => {
            // C: `if(optind >= argc) return cmd_shell(...)` — bare
            // `tinc` enters interactive shell mode. We don't have
            // shell mode (5b). Print help, exit 1. Matches what
            // `git` does for bare `git`.
            eprintln!("No command given.");
            eprintln!("Try `tinc --help' for more information.");
            return ExitCode::FAILURE;
        }
        Some(_) => {}
    }

    let cmd_name = &rest[0];
    let cmd_args = &rest[1..];

    // ─── Dispatch ───────────────────────────────────────────────────
    // C: linear scan of `commands[]` with `strcasecmp`. We use
    // `eq_ignore_ascii_case` (same as strcasecmp on ASCII; we already
    // pinned everything to ASCII in tinc-conf for the same reason).
    // Yes, `tinc INIT alice` works in the C. Preserved because it's
    // free.
    let Some(entry) = COMMANDS
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(cmd_name))
    else {
        eprintln!("Unknown command `{cmd_name}'.");
        eprintln!("Try `tinc --help' for more information.");
        return ExitCode::FAILURE;
    };

    // Paths resolved *after* dispatch lookup. C resolves before
    // (`make_names` runs in `main` before `run_command`). We move it
    // here so a typo'd command name fails fast without touching the
    // filesystem (`for_cli` doesn't, but a future for_cli might
    // probe). Micro-optimization; the order doesn't matter for any
    // current command.
    let paths = Paths::for_cli(&input);

    match (entry.run)(&paths, cmd_args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
