//! The `tinc` CLI binary.
//!
//! ## Dispatch
//!
//! The dispatch table (`COMMANDS`) is the same shape as upstream's
//! `commands[]` array; adding a command is one entry + one module in
//! `cmd/`. The argv parsing and `Paths` resolution are done once,
//! here, and every command gets them pre-chewed.
//!
//! Each entry carries a `Run` variant that encodes the command's
//! arity. `main` validates the positional count centrally and hands
//! the typed argument(s) straight to the library function — most
//! entries point at `cmd::*` with no per-command adapter at all. Only
//! the genuinely irregular commands (`init` reads stdin, `fsck`
//! prints a report, `config`/`dump` sub-dispatch, …) keep a bespoke
//! `fn(&Paths, &Globals, &[String])`.
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
//! Upstream returns 1 on any error. So do we. There's no
//! granular exit code tradition to preserve.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_tools::cmd::{self, CmdError};
use tinc_tools::names::{Paths, PathsInput};

/// How a command consumes its positionals. `main` does the arity
/// check so individual entries don't repeat the same `match args`.
///
/// Variants that don't carry `&Globals` cover the majority of
/// commands and let the table point straight at `cmd::*` functions
/// (e.g. `Run::N0(cmd::ctl_simple::stop)`). The handful that need
/// `--force` / `netname` or do their own argv surgery use `Any`.
enum Run {
    /// Exactly zero positionals.
    N0(fn(&Paths) -> Result<(), CmdError>),
    /// Exactly one positional. The `&str` is the name used in the
    /// `MissingArg` error.
    N1(&'static str, fn(&Paths, &str) -> Result<(), CmdError>),
    /// Zero or one positional.
    Opt(fn(&Paths, Option<&str>) -> Result<(), CmdError>),
    /// Anything; the handler validates (or ignores) arity itself.
    Any(fn(&Paths, &Globals, &[String]) -> Result<(), CmdError>),
}

/// One row of the dispatch table. Name, handler, one-line help.
struct CmdEntry {
    name: &'static str,
    /// When `true`, `main()` calls `paths.resolve_runtime()` before
    /// dispatch. The fs probe (`access(2)` on `/var/run/tinc.pid`)
    /// only fires for commands that need it. Filesystem commands
    /// like `init` and `export` never reach for `pidfile()`, so the
    /// `Option<PathBuf>` stays `None` and the panic-on-unresolved
    /// catches accidental use.
    ///
    /// Why a flag and not a second table: the handler signature is
    /// the same. `connect()` takes `&Paths` and creates the socket
    /// internally. Same shape, one table.
    needs_daemon: bool,
    run: Run,
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
    /// `--force`. Currently used by: `import`
    /// (overwrite existing), eventually `set` (allow obsolete vars).
    force: bool,
    /// `-n NETNAME` after `.` → None normalization. Separate from
    /// `Paths` because `Paths` only carries the *resolved* confbase,
    /// not the original netname — but `tinc invite` needs the netname
    /// to write into the invitation file (`NetName = X` line).
    netname: Option<String>,
}

/// The `commands[]` dispatch table.
///
/// Filesystem and daemon-RPC commands share one table. The
/// `needs_daemon` flag drives whether `resolve_runtime()` runs
/// before dispatch.
const COMMANDS: &[CmdEntry] = &[
    CmdEntry {
        name: "init",
        needs_daemon: false,
        run: Run::Any(cmd_init),
        help: "init NAME              Create initial configuration files.",
    },
    CmdEntry {
        name: "export",
        needs_daemon: false,
        run: Run::N0(cmd_export),
        help: "export                 Export host configuration of local node to standard output",
    },
    CmdEntry {
        name: "export-all",
        needs_daemon: false,
        run: Run::N0(cmd_export_all),
        help: "export-all             Export all host configuration files to standard output",
    },
    CmdEntry {
        name: "import",
        needs_daemon: false,
        run: Run::Any(cmd_import),
        help: "import                 Import host configuration file(s) from standard input",
    },
    CmdEntry {
        name: "exchange",
        needs_daemon: false,
        run: Run::Any(cmd_exchange),
        help: "exchange               Same as export followed by import",
    },
    CmdEntry {
        name: "exchange-all",
        needs_daemon: false,
        run: Run::Any(cmd_exchange_all),
        help: "exchange-all           Same as export-all followed by import",
    },
    CmdEntry {
        name: "generate-ed25519-keys",
        needs_daemon: false,
        run: Run::N0(cmd::genkey::run),
        help: "generate-ed25519-keys  Generate a new Ed25519 key pair.",
    },
    // `generate-rsa-keys`/`generate-keys`: warn-and-succeed RSA stub.
    // The NixOS module's preStart calls `tinc generate-rsa-keys 4096`
    // unconditionally; rejecting it would break every deployment.
    CmdEntry {
        name: "generate-rsa-keys",
        needs_daemon: false,
        run: Run::Opt(cmd_genkey_rsa_stub),
        help: "generate-rsa-keys      (no-op: this build is Ed25519-only)",
    },
    CmdEntry {
        name: "generate-keys",
        needs_daemon: false,
        run: Run::N0(cmd::genkey::run), // Ed25519 half only
        help: "generate-keys          Generate new keys (Ed25519 only).",
    },
    CmdEntry {
        name: "sign",
        needs_daemon: false,
        run: Run::Opt(cmd_sign),
        help: "sign [FILE]            Generate a signed version of a file.",
    },
    CmdEntry {
        name: "verify",
        needs_daemon: false,
        run: Run::Any(cmd_verify),
        help: "verify NODE [FILE]     Verify that a file was signed by the given NODE.",
    },
    CmdEntry {
        name: "fsck",
        needs_daemon: false,
        run: Run::Any(cmd_fsck),
        help: "fsck                   Check the configuration files for problems.",
    },
    CmdEntry {
        name: "invite",
        // `needs_daemon: true` not because invite *requires* the
        // daemon, but so `resolve_runtime()` runs and we can attempt
        // a best-effort reload after generating a fresh invitation
        // key. The first invitation on a running daemon is otherwise
        // unredeemable until manual restart.
        needs_daemon: true,
        run: Run::Any(cmd_invite),
        help: "invite NODE            Generate an invitation for NODE.",
    },
    CmdEntry {
        name: "join",
        needs_daemon: false,
        run: Run::Any(cmd_join),
        help: "join INVITATION        Join a VPN using an invitation.",
    },
    // ─── daemon RPC
    // `start`/`restart`: not really daemon-RPC (they *spawn* the
    // daemon) but `needs_daemon: true` gets us `resolve_runtime()`
    // — `cmd::start` needs `paths.pidfile()` and `paths.unix_socket()`
    // both for the already-running check (`CtlSocket::connect`) and
    // to pass `--pidfile`/`--socket` explicitly to the spawned tincd.
    CmdEntry {
        name: "start",
        needs_daemon: true,
        run: Run::Any(cmd_start),
        help: "start [tincd OPTIONS]  Start tincd.",
    },
    CmdEntry {
        name: "restart",
        needs_daemon: true,
        run: Run::Any(cmd_restart),
        help: "restart [tincd OPTIONS]  Restart tincd.",
    },
    CmdEntry {
        name: "pid",
        needs_daemon: true,
        run: Run::N0(cmd_pid),
        help: "pid                    Show PID of currently running tincd.",
    },
    CmdEntry {
        name: "stop",
        needs_daemon: true,
        run: Run::N0(cmd::ctl_simple::stop),
        help: "stop                   Stop tincd.",
    },
    CmdEntry {
        name: "reload",
        needs_daemon: true,
        run: Run::N0(cmd::ctl_simple::reload),
        help: "reload                 Partially reload configuration of running tincd.",
    },
    CmdEntry {
        name: "retry",
        needs_daemon: true,
        run: Run::N0(cmd::ctl_simple::retry),
        help: "retry                  Retry all outgoing connections.",
    },
    CmdEntry {
        name: "purge",
        needs_daemon: true,
        run: Run::N0(cmd::ctl_simple::purge),
        help: "purge                  Purge unreachable nodes.",
    },
    CmdEntry {
        name: "debug",
        needs_daemon: true,
        run: Run::Opt(cmd_debug),
        help: "debug [N]              Show or set debug level.",
    },
    CmdEntry {
        name: "disconnect",
        needs_daemon: true,
        run: Run::N1("node name", cmd::ctl_simple::disconnect),
        help: "disconnect NODE        Close meta connection with NODE.",
    },
    // ─── cmd_config: get/set/add/del + the `config` umbrella
    // Five entries route to one function. Upstream does `if(strcasecmp(argv[0], "config")) { argv--; argc++; }`
    // — if you typed `tinc add Foo bar`, shift argv back so
    // `argv[1]` is `add` again, then dispatch on it. We do the
    // shift in cmd_config_dispatch.
    //
    // `needs_daemon: true` for ALL of them — even `get` (it might
    // hit the Port-from-pidfile path). The `set`/`add`/`del` need
    // it for the post-edit reload. Upstream's `ctl` is `true` only
    // for `config`; the aliases are `false`. Inconsistent (the
    // author probably forgot). We're consistent: all `true`.
    CmdEntry {
        name: "get",
        needs_daemon: true,
        run: Run::Any(cmd_get),
        help: "get VARIABLE           Print current value of VARIABLE",
    },
    CmdEntry {
        name: "set",
        needs_daemon: true,
        run: Run::Any(cmd_set),
        help: "set VARIABLE VALUE     Set VARIABLE to VALUE",
    },
    CmdEntry {
        name: "add",
        needs_daemon: true,
        run: Run::Any(cmd_add),
        help: "add VARIABLE VALUE     Add VARIABLE with the given VALUE",
    },
    CmdEntry {
        name: "del",
        needs_daemon: true,
        run: Run::Any(cmd_del),
        help: "del VARIABLE [VALUE]   Remove VARIABLE [only ones with matching VALUE]",
    },
    // The `config` umbrella: `tinc config get Port` ≡ `tinc get
    // Port`. No help line — it's a verbosity nobody types. The
    // aliases are the user-facing names.
    CmdEntry {
        name: "config",
        needs_daemon: true,
        run: Run::Any(cmd_config_umbrella),
        help: "",
    },
    // ─── dump: nodes/edges/subnets/connections/graph/invitations
    // `dump` and `list` both → cmd_dump.
    //
    // `needs_daemon: true` even though `dump invitations` is pure
    // readdir. Upstream has `ctl=false` and connects INSIDE cmd_dump
    // after the kind switch. We can't — `resolve_runtime` is `&mut`.
    // So: resolve unconditionally. `dump invitations` pays one
    // harmless `access(2)` probe and never calls `pidfile()`.
    CmdEntry {
        name: "dump",
        needs_daemon: true,
        run: Run::Any(cmd_dump),
        help: concat!(
            "dump                   Dump a list of one of the following things:\n",
            "    [reachable] nodes        - all known nodes in the VPN\n",
            "    edges                    - all known connections in the VPN\n",
            "    subnets                  - all known subnets in the VPN\n",
            "    connections              - all meta connections with ourself\n",
            "    [di]graph                - graph of the VPN in dotty format\n",
            "    invitations              - outstanding invitations",
        ),
    },
    // Exact alias. No help line (it's `dump` by another name).
    CmdEntry {
        name: "list",
        needs_daemon: true,
        run: Run::Any(cmd_dump),
        help: "",
    },
    CmdEntry {
        name: "info",
        needs_daemon: true,
        run: Run::N1("node name, subnet, or address", cmd_info),
        help: "info NODE|SUBNET|ADDRESS    Give information about a particular NODE, SUBNET or ADDRESS.",
    },
    CmdEntry {
        name: "top",
        needs_daemon: true,
        run: Run::Any(cmd_top),
        help: "top                         Show real-time statistics",
    },
    CmdEntry {
        name: "log",
        needs_daemon: true,
        run: Run::Opt(cmd_log),
        help: "log [level]                 Dump log output [up to the specified level]",
    },
    CmdEntry {
        name: "pcap",
        needs_daemon: true,
        run: Run::Opt(cmd_pcap),
        help: "pcap [snaplen]              Dump traffic in pcap format [up to snaplen bytes per packet]",
    },
    // ─── edit: spawn $EDITOR on a config file, then reload
    // `needs_daemon: true` so the pidfile path gets resolved (the
    // silent reload needs it). The connect-can-fail is INSIDE
    // cmd::edit::run.
    CmdEntry {
        name: "edit",
        needs_daemon: true,
        run: Run::N1("FILE", cmd::edit::run),
        help: "edit FILE                   Edit a config file with $VISUAL/$EDITOR/vi",
    },
    // ─── version, help: trivial dispatchers
    // Help text is empty: listing `help` in `--help`'s output is
    // recursive; the user already found it.
    CmdEntry {
        name: "version",
        needs_daemon: false,
        run: Run::N0(cmd_version),
        help: "",
    },
    CmdEntry {
        name: "help",
        needs_daemon: false,
        run: Run::Any(cmd_help),
        help: "",
    },
    // ─── network: list networks under confdir
    // Upstream has TWO modes (list / switch); we only have list. The
    // switch is C-behavior-drop #2 — only useful in the readline
    // loop, which we don't have. `tinc network NAME` errors with
    // "use -n NAME" advice.
    CmdEntry {
        name: "network",
        needs_daemon: false,
        run: Run::Opt(cmd::network::run),
        help: "network                List all known networks (to switch, use -n NETNAME)",
    },
];

// ─────────────────────────────────────────────────────────────────────
// Adapters that can't point straight at a `cmd::*` function: they
// read `Globals`, print to stdout/stderr, parse a sub-argument, or
// have irregular arity. Everything else is wired directly in the
// table above.
// ─────────────────────────────────────────────────────────────────────

/// Arity guard for the few `Run::Any` handlers that still want zero
/// positionals but also need `&Globals`.
fn no_args(args: &[String]) -> Result<(), CmdError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(CmdError::TooManyArgs)
    }
}

/// `init`: name on argv or piped on stdin (so `echo NAME | tinc -c X
/// init` scripts written for C tinc keep working). No tty prompt.
fn cmd_init(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    use std::io::{IsTerminal, Read};
    match args {
        [name] => cmd::init::run(paths, name),
        [] => {
            if std::io::stdin().is_terminal() {
                return Err(CmdError::MissingArg("Name"));
            }
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| CmdError::BadInput(format!("Error reading stdin: {e}")))?;
            // C reads one `fgets` line; take the first so trailing
            // garbage on stdin doesn't fold into the name.
            let name = buf.lines().next().unwrap_or("").trim();
            if name.is_empty() {
                return Err(CmdError::MissingArg("Name"));
            }
            cmd::init::run(paths, name)
        }
        [_, _, ..] => Err(CmdError::TooManyArgs),
    }
}

/// `cmd_generate_rsa_keys` under `DISABLE_LEGACY`: warn, succeed.
/// Accepts the optional `[bits]` arg (NixOS module passes `4096`).
#[allow(clippy::unnecessary_wraps)]
fn cmd_genkey_rsa_stub(_: &Paths, _: Option<&str>) -> Result<(), CmdError> {
    eprintln!(
        "Warning: this tinc was built without legacy protocol support; skipping RSA key generation."
    );
    Ok(())
}

fn cmd_sign(paths: &Paths, input: Option<&str>) -> Result<(), CmdError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    #[allow(clippy::cast_possible_wrap)] // unix time fits i64 until year 292e9
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;
    cmd::sign::sign(
        paths,
        input.map(std::path::Path::new),
        t,
        std::io::stdout().lock(),
    )
}

/// `fsck` never `Err`s on findings — its job is to report, not
/// propagate. `Report::ok` maps to exit code via an empty `BadInput`
/// so the dispatch table keeps one `Result` shape.
fn cmd_fsck(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    use cmd::fsck::Severity;

    no_args(args)?;

    // Reconstruct the `tinc -c CONFBASE` prefix for suggestion
    // messages. Slightly less pretty than the C (which would say
    // `tinc -n NETNAME` if you used `-n`), but always correct.
    let cmd_prefix = format!("tinc -c {}", paths.confbase.display());

    let report = cmd::fsck::run(paths, g.force)?;

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

    if report.ok {
        Ok(())
    } else {
        // Empty message → main() skips the eprintln; diagnostics
        // already printed above.
        Err(CmdError::BadInput(String::new()))
    }
}

/// Prints the URL to stdout (the only thing on stdout, so
/// `tinc invite alice | mail alice@example` works). Warnings to
/// stderr.
fn cmd_invite(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    let [invitee] = args else {
        return Err(if args.is_empty() {
            CmdError::MissingArg("node name")
        } else {
            CmdError::TooManyArgs
        });
    };

    let r = cmd::invite::invite(
        paths,
        g.netname.as_deref(),
        invitee,
        std::time::SystemTime::now(),
    )?;

    if r.key_is_new {
        // The daemon loads `invitations/ed25519_key.priv` at startup;
        // a freshly-generated key is invisible to a running daemon
        // until reload. Best-effort: if it's up, ask; if not (or the
        // reload nacks), fall back to the manual-restart hint.
        if cmd::ctl_simple::reload(paths).is_err() {
            eprintln!(
                "Could not signal the tinc daemon. \
                 Please restart or reload it manually."
            );
        }
    }

    // The URL is the secret. stdout only.
    println!("{}", *r.url);
    Ok(())
}

fn cmd_pid(paths: &Paths) -> Result<(), CmdError> {
    println!("{}", cmd::ctl_simple::pid(paths)?);
    Ok(())
}

/// Everything after `start` becomes a tincd arg.
/// `tinc start -d 5` → `tincd -c … --pidfile … --socket … -d 5`.
#[cfg(unix)]
fn cmd_start(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    cmd::start::start(paths, args)
}

#[cfg(unix)]
fn cmd_restart(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    cmd::start::restart(paths, args)
}

/// `debug`: with arg, set level; without, query (our extension —
/// upstream requires the arg, but the daemon already supports `-1`
/// as "return current without changing").
fn cmd_debug(paths: &Paths, arg: Option<&str>) -> Result<(), CmdError> {
    let level = match arg {
        None => -1,
        Some(lvl) => lvl
            .parse()
            .map_err(|_| CmdError::BadInput(format!("Invalid debug level {lvl:?}.")))?,
    };
    let prev = cmd::ctl_simple::debug(paths, level)?;
    if level < 0 {
        println!("{prev}");
    } else {
        // `"Old level %d, new level %d.\n"` to stderr (yes, stderr).
        eprintln!("Old level {prev}, new level {level}.");
    }
    Ok(())
}

/// `cmd_config` core. The `action` is decided by the caller — either
/// from the toplevel command name (get/set/add/del adapters below)
/// or from `tinc config <verb>` peeling (`cmd_config_umbrella`).
///
/// `args` here is everything AFTER the verb — `["Port", "655"]` for
/// `tinc set Port 655`.
fn cmd_config_with_action(
    paths: &Paths,
    g: &Globals,
    action: cmd::config::Action,
    args: &[String],
) -> Result<(), CmdError> {
    if args.is_empty() {
        return Err(CmdError::BadInput("Invalid number of arguments.".into()));
    }

    // Space-join recreates `tinc set Name foo bar` → var=Name,
    // val="foo bar" (collapses shell-quoted spaces; so does the C).
    let joined = args.join(" ");

    let (out, warnings) = cmd::config::run(paths, action, &joined, g.force)?;
    config_output(paths, out, &warnings);
    Ok(())
}

/// Print the result. Factored out so the integration tests can see
/// the contract: `Got` → stdout one-per-line, `Edited` → reload.
fn config_output(paths: &Paths, out: cmd::config::ConfigOutput, warnings: &[cmd::config::Warning]) {
    use cmd::config::ConfigOutput;

    for w in warnings {
        eprintln!("{w}");
    }

    match out {
        ConfigOutput::Got(values) => {
            for v in values {
                println!("{v}");
            }
        }
        ConfigOutput::Edited => {
            // Best-effort: file's already written; daemon down or
            // reload-nack are both fine, it picks up on next start.
            let _ = cmd::ctl_simple::reload(paths);
        }
    }
}

// Four toplevel adapters: dispatch ate argv[0], so each passes its
// action explicitly. Don't unify via re-parsing args[0] — the GET
// fall-through default would mis-route `add` as a destructive SET.

fn cmd_get(p: &Paths, g: &Globals, a: &[String]) -> Result<(), CmdError> {
    cmd_config_with_action(p, g, cmd::config::Action::Get, a)
}
fn cmd_set(p: &Paths, g: &Globals, a: &[String]) -> Result<(), CmdError> {
    cmd_config_with_action(p, g, cmd::config::Action::Set, a)
}
fn cmd_add(p: &Paths, g: &Globals, a: &[String]) -> Result<(), CmdError> {
    cmd_config_with_action(p, g, cmd::config::Action::Add, a)
}
fn cmd_del(p: &Paths, g: &Globals, a: &[String]) -> Result<(), CmdError> {
    cmd_config_with_action(p, g, cmd::config::Action::Del, a)
}

/// `tinc config <verb> ...`. The umbrella form. `tinc config Port`
/// (no verb) → default GET. `replace`/`change` are aliases for `set`
/// — only available here, not as toplevel commands; same as upstream.
fn cmd_config_umbrella(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    use cmd::config::Action;

    let (action, rest) = match args.split_first() {
        Some((v, r)) if v.eq_ignore_ascii_case("get") => (Action::Get, r),
        Some((v, r)) if v.eq_ignore_ascii_case("add") => (Action::Add, r),
        Some((v, r)) if v.eq_ignore_ascii_case("del") => (Action::Del, r),
        Some((v, r))
            if v.eq_ignore_ascii_case("set")
                || v.eq_ignore_ascii_case("replace")
                || v.eq_ignore_ascii_case("change") =>
        {
            (Action::Set, r)
        }
        // `tinc config Port` → GET. Safe here: this fn ONLY routes
        // from the `config` table entry, never from add/del.
        _ => (Action::Get, args),
    };
    cmd_config_with_action(paths, g, action, rest)
}

/// Two-stage dispatch: argv → `Kind`, then `Kind` → connect-or-readdir.
fn cmd_dump(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    use cmd::dump::{Kind, dump, dump_invitations, parse_kind};

    let kind = parse_kind(args)?;

    // Invitations: pure readdir, no daemon. Works daemon-down.
    if kind == Kind::Invitations {
        let rows = dump_invitations(paths)?;
        if rows.is_empty() {
            // stderr, exit 0 — scripts parsing `| while read` don't
            // want a non-data line on stdout.
            eprintln!("No outstanding invitations.");
        } else {
            for r in rows {
                println!("{} {}", r.cookie_hash, r.invitee);
            }
        }
        return Ok(());
    }

    for line in dump(paths, kind)? {
        println!("{line}");
    }
    Ok(())
}

/// Bimodal output: node → one big block; subnet → zero-to-many
/// `Subnet:/Owner:` pairs.
fn cmd_info(paths: &Paths, item: &str) -> Result<(), CmdError> {
    use cmd::info::{InfoOutput, info};

    match info(paths, item)? {
        // `print!` not `println!` — NodeInfo::format ends every line
        // with `\n` already.
        InfoOutput::Node(s) => {
            print!("{s}");
        }
        InfoOutput::Subnet(matches) => {
            for m in matches {
                println!("Subnet: {}", m.subnet);
                println!("Owner:  {}", m.owner);
            }
        }
    }
    Ok(())
}

/// The TUI loop. Doesn't return until 'q' or daemon death.
/// `g.netname` for the row-0 header.
fn cmd_top(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::top::run(paths, g.netname.as_deref())
}

/// `tinc log` → daemon's level. `tinc log 5` → filter at 5.
/// `parse::<i32>()` rejects garbage; C's `atoi` returns 0. The
/// change is observable only for invalid input — better.
fn cmd_log(paths: &Paths, arg: Option<&str>) -> Result<(), CmdError> {
    let level = arg
        .map(|lvl| {
            lvl.parse::<i32>()
                .map_err(|_| CmdError::BadInput(format!("Invalid debug level: {lvl}")))
        })
        .transpose()?;
    cmd::stream::run_log(paths, level)
}

/// `parse::<u32>()` rejects negative — `atoi("-5")` would
/// implicit-cast to a huge `uint32_t`. `tinc pcap -5` failing is
/// better than silently capturing 4GiB packets.
fn cmd_pcap(paths: &Paths, arg: Option<&str>) -> Result<(), CmdError> {
    let snaplen = match arg {
        None => 0,
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| CmdError::BadInput(format!("Invalid snaplen: {s}")))?,
    };
    cmd::stream::run_pcap(paths, snaplen)
}

#[allow(clippy::unnecessary_wraps)]
fn cmd_version(_: &Paths) -> Result<(), CmdError> {
    print_version();
    Ok(())
}

/// Upstream IGNORES args; `tinc help foo` ≡ `tinc help`.
#[allow(clippy::unnecessary_wraps)]
fn cmd_help(_: &Paths, _: &Globals, _: &[String]) -> Result<(), CmdError> {
    print_help();
    Ok(())
}

/// URL on argv or piped on stdin (no tty prompt — same "no prompts"
/// deviation as elsewhere). `--force` propagates to `finalize_join`'s
/// `VAR_SAFE` override.
fn cmd_join(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    use std::io::Read;

    let url_buf;
    let url: &str = match args {
        [u] => u,
        [] => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| CmdError::BadInput(format!("Error reading stdin: {e}")))?;
            url_buf = buf;
            url_buf.trim()
        }
        _ => return Err(CmdError::TooManyArgs),
    };

    cmd::join::join(url, paths, g.force)
}

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

fn cmd_export(paths: &Paths) -> Result<(), CmdError> {
    cmd::exchange::export(paths, std::io::stdout().lock())
}

fn cmd_export_all(paths: &Paths) -> Result<(), CmdError> {
    cmd::exchange::export_all(paths, std::io::stdout().lock())
}

/// Maps count→exit-code: returns 1 if zero imported.
fn cmd_import(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    let count = cmd::exchange::import(paths, std::io::stdin().lock(), g.force)?;
    if count > 0 {
        eprintln!("Imported {count} host configuration files.");
        Ok(())
    } else {
        Err(CmdError::BadInput(
            "No host configuration files imported.".into(),
        ))
    }
}

/// Export then import, no explicit close. The C `fclose(stdout)`
/// (gated on `!tty`) may be a workaround for pipe-buffer exhaustion
/// when exchanging many large hosts over ssh; if exchange-over-ssh
/// hangs in practice, revisit.
fn cmd_exchange(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd_export(paths)?;
    cmd_import(paths, g, args)
}

fn cmd_exchange_all(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd_export_all(paths)?;
    cmd_import(paths, g, args)
}

/// Match `arg` against one getopt-style value option in all four
/// spellings (`-x VAL`, `-xVAL`, `--long VAL`, `--long=VAL`). Returns
/// `Ok(Some(value))` on match, `Ok(None)` if `arg` is something else,
/// `Err` if it matched but the separate-argument form had no follower.
fn take_opt(
    arg: &str,
    it: &mut impl Iterator<Item = String>,
    short: Option<&str>,
    long: &str,
) -> Result<Option<String>, String> {
    if short == Some(arg) || arg == long {
        let name = short.unwrap_or(long);
        return it
            .next()
            .map(Some)
            .ok_or_else(|| format!("option {name} requires an argument"));
    }
    if let Some(rest) = arg.strip_prefix(long).and_then(|r| r.strip_prefix('=')) {
        return Ok(Some(rest.to_owned()));
    }
    if let Some(s) = short
        && let Some(rest) = arg.strip_prefix(s)
        && !rest.is_empty()
    {
        return Ok(Some(rest.to_owned()));
    }
    Ok(None)
}

/// `Err(String)` is the message to print before exiting nonzero.
fn parse_global_options(
    mut args: impl Iterator<Item = String>,
) -> Result<(PathsInput, Globals, Vec<String>), String> {
    let mut input = PathsInput::default();
    // netname is captured into Globals in main() after `.` → None
    // normalization; this fn only parses argv.
    let mut globals = Globals {
        force: false,
        netname: None,
    };
    let mut rest = Vec::new();

    // `getopt_long(argc, argv, "+bc:n:", ...)` — the `+` means stop
    // at first non-option. We loop until we hit something that doesn't
    // start with `-`, then dump everything remaining into `rest`.
    while let Some(arg) = args.next() {
        if let Some(v) = take_opt(&arg, &mut args, Some("-c"), "--config")? {
            input.confbase = Some(PathBuf::from(v));
            continue;
        }
        if let Some(v) = take_opt(&arg, &mut args, Some("-n"), "--net")? {
            input.netname = Some(v);
            continue;
        }
        // `--pidfile=FILE`. Overrides the /var/run ↔ confbase
        // resolution dance entirely. Only matters for daemon-RPC
        // commands. No short form (C: long-only).
        if let Some(v) = take_opt(&arg, &mut args, None, "--pidfile")? {
            input.pidfile = Some(PathBuf::from(v));
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => {
                // Short-circuit via sentinel rest vec — avoids a
                // third Result variant. The caller checks for this.
                rest.push("--help".into());
                return Ok((input, globals, rest));
            }
            "--version" => {
                rest.push("--version".into());
                return Ok((input, globals, rest));
            }
            // `OPT_BATCH`: no-op (we never prompt). Accept-and-ignore
            // for compat with scripts that pass it.
            "-b" | "--batch" => {}
            "--force" => {
                globals.force = true;
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown option: {s}"));
            }
            // First non-option: subcommand name. Everything after is
            // positional, even if it starts with `-` (getopt `+` mode).
            _ => {
                rest.push(arg);
                rest.extend(args);
                break;
            }
        }
    }

    // NETNAME env fallback (only if -n wasn't given).
    if input.netname.is_none()
        && let Ok(env_net) = env::var("NETNAME")
    {
        input.netname = Some(env_net);
    }

    // "." is the "top-level" sentinel — "no netname, use confdir as
    // confbase". Lets `NETNAME=.` in env explicitly say "I want
    // /etc/tinc not /etc/tinc/$NETNAME".
    if matches!(input.netname.as_deref(), Some("" | ".")) {
        input.netname = None;
    }

    // Path-traversal guard: netname becomes a path component; slashes
    // would escape confdir. Leading dot rejects `..`. Weaker than
    // `check_id` on purpose — netname is a local fs thing, not a wire
    // protocol token.
    if let Some(net) = &input.netname
        && (net.starts_with('.') || net.contains('/') || net.contains('\\'))
    {
        return Err("Invalid character in netname!".into());
    }

    Ok((input, globals, rest))
}

fn print_help() {
    // The `help` strings were written ad-hoc with varying column
    // widths; re-pad here so the description column lines up no
    // matter which entry was added last. Each help string is
    // `"NAME ARGS   description"` (≥2 spaces separate the columns);
    // continuation lines (the `dump` sub-list) are passed through
    // verbatim.
    const COL: usize = 25;

    println!("Usage: tinc [OPTION]... COMMAND [ARGS]...");
    println!();
    println!("Options:");
    println!("  -c, --config=DIR    Read configuration from DIR.");
    println!("  -n, --net=NETNAME   Connect to net NETNAME.");
    println!("  -b, --batch         Don't ask for anything (no-op; we never prompt).");
    println!("      --pidfile=FILE  Read control cookie from FILE.");
    println!("      --force         Force some commands to work despite warnings.");
    println!("      --help          Display this help and exit.");
    println!("      --version       Output version information and exit.");
    println!();
    println!("Commands:");
    for c in COMMANDS {
        if c.help.is_empty() {
            continue;
        }
        for (i, line) in c.help.lines().enumerate() {
            if i == 0
                && let Some((lhs, rhs)) = line.split_once("  ")
            {
                println!("  {lhs:<COL$} {}", rhs.trim_start());
            } else {
                println!("  {line}");
            }
        }
    }
    println!();
    println!("Report bugs to https://github.com/Mic92/tincr/issues.");
}

fn print_version() {
    // "(Rust)" suffix so `tinc --version` in a bug report tells you
    // immediately which binary you're running.
    println!("tinc {} (Rust)", env!("CARGO_PKG_VERSION"));
}

fn main() -> ExitCode {
    let (input, globals, rest) = match parse_global_options(env::args().skip(1)) {
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
            // Upstream enters interactive shell mode here. We don't
            // have shell mode; print help, exit 1 (like bare `git`).
            eprintln!("No command given.");
            eprintln!("Try `tinc --help' for more information.");
            return ExitCode::FAILURE;
        }
        Some(_) => {}
    }

    let cmd_name = &rest[0];
    let cmd_args = &rest[1..];

    // Linear scan with `eq_ignore_ascii_case` (≡ strcasecmp on ASCII;
    // `tinc INIT alice` works in the C, preserved because it's free).
    let Some(entry) = COMMANDS
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(cmd_name))
    else {
        eprintln!("Unknown command `{cmd_name}'.");
        eprintln!("Try `tinc --help' for more information.");
        return ExitCode::FAILURE;
    };

    // Paths resolved *after* dispatch lookup so a typo'd command name
    // fails fast without touching the filesystem.
    let globals = Globals {
        netname: input.netname.clone(),
        ..globals
    };
    let mut paths = Paths::for_cli(&input);

    // Daemon-RPC commands need pidfile/socket resolved. The probe
    // touches the fs (`access(2)` on `/var/run/tinc.X.pid`) so we
    // only do it for commands that need it.
    if entry.needs_daemon {
        paths.resolve_runtime(&input);
    }

    // Central arity check. Adapters using `Run::Any` validate their
    // own (or deliberately ignore extras, like `help`).
    let result = match entry.run {
        Run::N0(f) => match cmd_args {
            [] => f(&paths),
            _ => Err(CmdError::TooManyArgs),
        },
        Run::N1(label, f) => match cmd_args {
            [] => Err(CmdError::MissingArg(label)),
            [a] => f(&paths, a),
            _ => Err(CmdError::TooManyArgs),
        },
        Run::Opt(f) => match cmd_args {
            [] => f(&paths, None),
            [a] => f(&paths, Some(a)),
            _ => Err(CmdError::TooManyArgs),
        },
        Run::Any(f) => f(&paths, &globals, cmd_args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Arity errors (`MissingArg` / `TooManyArgs`) on their own
            // tell the user *what* went wrong but not what to type
            // instead; append the command's one-line synopsis so they
            // don't have to re-run `--help` and scan 30 lines.
            //
            // `BadInput("")` is the fsck "already printed everything"
            // sentinel — don't add a spurious blank line.
            let msg = e.to_string();
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            if matches!(e, CmdError::MissingArg(_) | CmdError::TooManyArgs)
                && let Some(usage) = entry.help.lines().next()
                && !usage.is_empty()
            {
                let usage = usage.split_once("  ").map_or(usage, |(l, _)| l);
                eprintln!("Usage: tinc {usage}");
            }
            ExitCode::FAILURE
        }
    }
}
