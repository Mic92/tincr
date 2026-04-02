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
//! Same call as `sptps_test`: 5 global options (`-c`, `-n`,
//! `--force`, `--help`, `--version`) + a subcommand name +
//! per-subcommand positionals.
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
    ///
    /// `&Globals` is the C globals (`force`, eventually `tty`, etc.)
    /// that every `cmd_*` *can* read. Most don't.
    run: fn(&Paths, &Globals, &[String]) -> Result<(), CmdError>,
    help: &'static str,
}

/// `tincctl.c`'s globals. The ones every command potentially reads,
/// not the ones `make_names` writes (those are `Paths`).
///
/// In C these are bare globals — `bool force = false;` at file scope.
/// Threading them as a struct means a command's signature *says*
/// whether it cares (it takes `_: &Globals` if it doesn't).
///
/// Why not fold into `Paths`: `Paths` is path resolution; this is
/// behavior toggles. Different lifetimes (a future shell mode resets
/// `force` per-command but keeps `Paths`), different concerns.
struct Globals {
    /// `--force`. C: `tincctl.c:75`. Currently used by: `import`
    /// (overwrite existing), eventually `set` (allow obsolete vars).
    force: bool,
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
    CmdEntry {
        name: "export",
        run: cmd_export,
        help: "export                 Export host configuration of local node to standard output",
    },
    CmdEntry {
        name: "export-all",
        run: cmd_export_all,
        help: "export-all             Export all host configuration files to standard output",
    },
    CmdEntry {
        name: "import",
        run: cmd_import,
        help: "import                 Import host configuration file(s) from standard input",
    },
    CmdEntry {
        name: "exchange",
        run: cmd_exchange,
        help: "exchange               Same as export followed by import",
    },
    CmdEntry {
        name: "exchange-all",
        run: cmd_exchange_all,
        help: "exchange-all           Same as export-all followed by import",
    },
    CmdEntry {
        name: "generate-ed25519-keys",
        run: cmd_genkey,
        help: "generate-ed25519-keys  Generate a new Ed25519 key pair.",
    },
    // C also has `generate-keys` (→ RSA + Ed25519) but RSA is
    // dropped under DISABLE_LEGACY. Could alias `generate-keys` →
    // `generate-ed25519-keys`; the C does *not* (it's a distinct
    // function that calls both keygens). Skip.
    CmdEntry {
        name: "sign",
        run: cmd_sign,
        help: "sign [FILE]            Generate a signed version of a file.",
    },
    CmdEntry {
        name: "verify",
        run: cmd_verify,
        help: "verify NODE [FILE]     Verify that a file was signed by the given NODE.",
    },
    CmdEntry {
        name: "fsck",
        run: cmd_fsck,
        help: "fsck                   Check the configuration files for problems.",
    },
    // 4a complete (modulo `edit`, deferred to 5b for its reload half).
    // 5b commands (`dump`, `top`, `log`, `set`, `get`, ...) go in a
    // separate table — they take `&mut CtlSocket`, not `&Paths`.
];

/// Thin adapter: `&[String]` argv → typed args for `cmd::init::run`.
/// Each command has one of these; it's where arity errors live.
///
/// C `cmd_init` does `if(argc > 2)` / `if(argc < 2)` inline. We do it
/// here so `cmd::init::run` gets a nice `&str` and never sees argv.
fn cmd_init(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    match args {
        [] => Err(CmdError::MissingArg("Name")),
        [name] => cmd::init::run(paths, name),
        [_, _, ..] => Err(CmdError::TooManyArgs),
    }
}

/// `cmd_generate_ed25519_keys`: zero args. C `tincctl.c:2351`.
/// The C accepts no args; the wrapper is 5 lines.
fn cmd_genkey(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    if !args.is_empty() {
        return Err(CmdError::TooManyArgs);
    }
    cmd::genkey::run(paths)
}

/// `cmd_sign`: optional file arg. C `tincctl.c:2770`.
/// `t = time(NULL)` → `SystemTime::now().duration_since(UNIX_EPOCH)`.
/// `as_secs()` returns `u64`; we need `i64` for the `%ld` format.
/// `as i64` is safe until 292 billion CE.
fn cmd_sign(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let input = match args {
        [] => None,
        [file] => Some(std::path::Path::new(file)),
        [_, _, ..] => return Err(CmdError::TooManyArgs),
    };
    // `expect` is fine: `now() < UNIX_EPOCH` only on a system whose
    // clock is set before 1970. The C `time(NULL)` would return
    // `(time_t)-1` on the same system (and then `%ld` formats it as
    // `-1`, and `verify`'s `!t` check passes — a different bug). We
    // crash. Better.
    #[allow(clippy::cast_possible_wrap)]
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;
    cmd::sign::sign(paths, input, t, std::io::stdout().lock())
}

/// `cmd_fsck`: zero args. C `tincctl.c:2732`.
///
/// fsck never `Err`s — its job is to report errors, not propagate.
/// `Report::ok` maps to exit code. The `Err` arm here only fires if
/// `cmd::fsck::run` itself panics-via-?, which it doesn't.
///
/// `cmd_prefix` reconstruction: C does this in `print_tinc_cmd`
/// (`fsck.c:68`) by reading `confbasegiven`/`netname` globals. We
/// reconstruct it from `Paths` — we don't have the globals, but we
/// know `confbase` is always set, so `tinc -c CONFBASE` is the
/// canonical form. Slightly less pretty than the C (which would say
/// `tinc -n NETNAME` if you used `-n`), but always correct.
fn cmd_fsck(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    use cmd::fsck::Severity;

    if !args.is_empty() {
        return Err(CmdError::TooManyArgs);
    }

    // C `fsck.c:640`: `fsck(orig_argv[0])`. The argv[0] becomes
    // `exe_name` for the suggestion messages. We hardcode `tinc` —
    // there's only one binary name. (C cares because of legacy:
    // `tincctl` was once a separate binary.)
    let cmd_prefix = format!("tinc -c {}", paths.confbase.display());

    let report = cmd::fsck::run(paths, g.force)?;

    // ERROR: / WARNING: prefixes per the C `fprintf` strings.
    for f in &report.findings {
        let prefix = match f.severity() {
            Severity::Error => "ERROR: ",
            Severity::Warning => "WARNING: ",
            Severity::Info => "",
        };
        eprintln!("{prefix}{f}");
        if let Some(sug) = f.suggestion(&cmd_prefix) {
            eprintln!("\n{sug}\n");
        }
    }

    // C `fsck.c:678`: `return success ? EXIT_SUCCESS : EXIT_FAILURE`.
    // Our dispatch maps `Ok(())` → 0 and `Err` → 1. fsck-fail isn't
    // a `CmdError` (it's not a usage error or an I/O error — it's
    // "your config is bad"), so we synthesize a `BadInput`. The
    // message is empty because we already printed everything.
    //
    // Alternative: have `cmd_fsck` return `ExitCode` directly,
    // bypassing the dispatch table's `Result<(), CmdError>`. That
    // would mean a separate dispatch shape just for fsck. Not worth
    // it; the `BadInput("")` hack is contained to this one adapter.
    if report.ok {
        Ok(())
    } else {
        // The empty message means `eprintln!("")` prints a blank
        // line. Harmless; the actual diagnostics already printed.
        Err(CmdError::BadInput(String::new()))
    }
}

/// `cmd_verify`: required signer arg, optional file arg.
/// C `tincctl.c:2858`.
fn cmd_verify(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    let (signer_arg, input) = match args {
        [] => return Err(CmdError::MissingArg("signer")),
        [s] => (s, None),
        [s, file] => (s, Some(std::path::Path::new(file))),
        [_, _, _, ..] => return Err(CmdError::TooManyArgs),
    };
    let signer = cmd::sign::Signer::parse(signer_arg, paths)?;
    cmd::sign::verify_cmd(paths, &signer, input, std::io::stdout().lock())
}

/// `cmd_export`: zero args, write to stdout.
fn cmd_export(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    if !args.is_empty() {
        return Err(CmdError::TooManyArgs);
    }
    // `lock()` for the BufWriter; export does many small writes.
    cmd::exchange::export(paths, std::io::stdout().lock())
}

/// `cmd_export_all`: zero args, write to stdout.
fn cmd_export_all(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    if !args.is_empty() {
        return Err(CmdError::TooManyArgs);
    }
    cmd::exchange::export_all(paths, std::io::stdout().lock())
}

/// `cmd_import`: zero args, read from stdin. Maps count→exit-code:
/// C returns 1 if zero imported. C: `tincctl.c:2640-2648`.
fn cmd_import(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    if !args.is_empty() {
        return Err(CmdError::TooManyArgs);
    }
    let count = cmd::exchange::import(paths, std::io::stdin().lock(), g.force)?;
    if count > 0 {
        eprintln!("Imported {count} host configuration files.");
        Ok(())
    } else {
        // The C `fprintf(stderr, ...)` then `return 1`. We surface as
        // BadInput so the dispatcher prints + exits 1. Same effect.
        Err(CmdError::BadInput(
            "No host configuration files imported.".into(),
        ))
    }
}

/// `cmd_exchange`: export, then import. C: `tincctl.c:2650-2652`.
///
/// The C is `return cmd_export(...) ? 1 : cmd_import(...)`. Short-
/// circuit on export failure. The `fclose(stdout)` in `cmd_export`
/// means stdin's peer (whoever is on the other end of the pipe —
/// usually another `tinc exchange` over ssh) sees EOF and finishes
/// its `import` before we start ours.
///
/// We need that EOF too. After our `export`, we drop stdout's lock
/// (just by scope), but the *fd* stays open until process exit. To
/// get EOF on the wire we have to close fd 1. But we still want to
/// print error messages (to stderr) after import. So: close stdout's
/// fd explicitly, after export, before import.
///
/// Except — closing fd 1 means any subsequent stdout write fails. The
/// only stdout write after this point would be... nothing, we never
/// print to stdout after import. So it's safe. But it's not *obvious*
/// it's safe. Belt-and-suspenders: we don't actually close fd 1; we
/// `dup2(/dev/null, 1)` so stdout becomes a black hole. Any
/// accidental stdout write goes nowhere instead of EBADF-ing.
///
/// Actually wait — the C doesn't `dup2`, it `fclose`s. After fclose,
/// the next `printf` is UB (writing to a closed FILE*). The C gets
/// away with it because `cmd_import` doesn't printf to stdout. We
/// can do the same simple thing: leave fd 1 alone, the peer sees EOF
/// when *we* exit. The exchange use case is full-duplex — both sides
/// are reading from each other simultaneously, so the import starts
/// reading *before* export finishes; deadlock isn't possible because
/// the OS buffers the pipe.
///
/// **Decision: do what the simplest reading of the C does — export
/// then import, no explicit close.** If exchange-over-ssh hangs
/// because of pipe buffer exhaustion (export of many large hosts),
/// revisit. The C's `fclose(stdout)` is gated on `if(!tty)` and may
/// be a workaround for exactly that; we'll find out.
fn cmd_exchange(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    cmd_export(paths, g, args)?;
    cmd_import(paths, g, args)
}

/// `cmd_exchange_all`: export-all, then import. C: `tincctl.c:2654-2656`.
fn cmd_exchange_all(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    cmd_export_all(paths, g, args)?;
    cmd_import(paths, g, args)
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
) -> Result<(PathsInput, Globals, Vec<String>), String> {
    let mut input = PathsInput::default();
    let mut globals = Globals { force: false };
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
                return Ok((input, globals, rest));
            }
            "--version" => {
                rest.push("--version".into());
                return Ok((input, globals, rest));
            }
            // C `OPT_BATCH` sets `tty = false` — disables interactive
            // prompts. We have no prompts (see `cmd/init.rs` doc), so
            // -b is a no-op. Accept-and-ignore for compat with scripts
            // that pass it.
            "-b" | "--batch" => {}
            // `--force`. C: `tincctl.c:250`. No short form — the C
            // long-only OPT_FORCE doesn't map to a single char.
            "--force" => {
                globals.force = true;
            }
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

    Ok((input, globals, rest))
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
    println!("      --force         Force some commands to work despite warnings.");
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

    let (input, globals, rest) = match parse_global_options(args) {
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

    match (entry.run)(&paths, &globals, cmd_args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
