//! The `tinc` CLI binary.
//!
//! ## Dispatch
//!
//! The dispatch table (`COMMANDS`) is the same shape as upstream's
//! `commands[]` array; adding a command is one entry + one module in
//! `cmd/`. The argv parsing and
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
//! Upstream returns 1 on any error. So do we. There's no
//! granular exit code tradition to preserve.

// Silence pedantic lints that fight CLI binary patterns. Same set as
// sptps_test, same reasoning.
#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use tinc_tools::cmd::{self, CmdError};
use tinc_tools::names::{Paths, PathsInput};

/// One row of the dispatch table. Name, handler, one-line help.
struct CmdEntry {
    name: &'static str,
    /// `connect_tincd` commands. C: `commands[].ctl` (well — the C
    /// table doesn't actually have that flag; the C just calls
    /// `connect_tincd` inline in each cmd_*. But the *intent* is
    /// the same: some commands need the daemon, some don't.).
    ///
    /// When `true`, `main()` calls `paths.resolve_runtime()` before
    /// dispatch. The fs probe (`access(2)` on `/var/run/tinc.pid`)
    /// only fires for commands that need it. Filesystem commands
    /// like `init` and `export` never reach for `pidfile()`, so the
    /// `Option<PathBuf>` stays `None` and the panic-on-unresolved
    /// catches accidental use.
    ///
    /// Why a flag and not a second table: the handler signature is
    /// the same (`&Paths, &Globals, &[String]`). `connect()` takes
    /// `&Paths` and creates the socket internally. Same shape, one
    /// table.
    needs_daemon: bool,
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
    /// `--force`. Currently used by: `import`
    /// (overwrite existing), eventually `set` (allow obsolete vars).
    force: bool,
    /// `-n NETNAME` after `.` → None normalization. Separate from
    /// `Paths` because `Paths` only carries the *resolved* confbase,
    /// not the original netname — but `tinc invite` needs the netname
    /// to write into the invitation file (`NetName = X` line).
    /// `cmd_join` also needs it (it's the directory the new node's
    /// config goes in).
    netname: Option<String>,
}

/// The `commands[]` dispatch table.
///
/// Filesystem and daemon-RPC commands share one table — the
/// signature is the same after all (`connect()` takes `&Paths`,
/// creates its own socket). The `needs_daemon` flag drives whether
/// `resolve_runtime()` runs before dispatch.
const COMMANDS: &[CmdEntry] = &[
    CmdEntry {
        name: "init",
        needs_daemon: false,
        run: cmd_init,
        help: "init NAME              Create initial configuration files.",
    },
    CmdEntry {
        name: "export",
        needs_daemon: false,
        run: cmd_export,
        help: "export                 Export host configuration of local node to standard output",
    },
    CmdEntry {
        name: "export-all",
        needs_daemon: false,
        run: cmd_export_all,
        help: "export-all             Export all host configuration files to standard output",
    },
    CmdEntry {
        name: "import",
        needs_daemon: false,
        run: cmd_import,
        help: "import                 Import host configuration file(s) from standard input",
    },
    CmdEntry {
        name: "exchange",
        needs_daemon: false,
        run: cmd_exchange,
        help: "exchange               Same as export followed by import",
    },
    CmdEntry {
        name: "exchange-all",
        needs_daemon: false,
        run: cmd_exchange_all,
        help: "exchange-all           Same as export-all followed by import",
    },
    CmdEntry {
        name: "generate-ed25519-keys",
        needs_daemon: false,
        run: cmd_genkey,
        help: "generate-ed25519-keys  Generate a new Ed25519 key pair.",
    },
    // `generate-rsa-keys`/`generate-keys`: warn-and-succeed RSA stub.
    // The NixOS module's preStart calls `tinc generate-rsa-keys 4096`
    // unconditionally; rejecting it would break every deployment.
    CmdEntry {
        name: "generate-rsa-keys",
        needs_daemon: false,
        run: cmd_genkey_rsa_stub,
        help: "generate-rsa-keys      (no-op: this build is Ed25519-only)",
    },
    CmdEntry {
        name: "generate-keys",
        needs_daemon: false,
        run: cmd_genkey, // Ed25519 half only
        help: "generate-keys          Generate new keys (Ed25519 only).",
    },
    CmdEntry {
        name: "sign",
        needs_daemon: false,
        run: cmd_sign,
        help: "sign [FILE]            Generate a signed version of a file.",
    },
    CmdEntry {
        name: "verify",
        needs_daemon: false,
        run: cmd_verify,
        help: "verify NODE [FILE]     Verify that a file was signed by the given NODE.",
    },
    CmdEntry {
        name: "fsck",
        needs_daemon: false,
        run: cmd_fsck,
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
        run: cmd_invite,
        help: "invite NODE            Generate an invitation for NODE.",
    },
    CmdEntry {
        name: "join",
        needs_daemon: false,
        run: cmd_join,
        help: "join INVITATION        Join a VPN using an invitation.",
    },
    // ─── daemon RPC
    // The simple ones. Each is `connect → send → ack → check`.
    // `dump`/`top`/`log`/`pcap` are the complex ones — streaming or
    // multi-row — they land separately.
    //
    // `start`/`restart`: not really daemon-RPC (they *spawn* the
    // daemon) but `needs_daemon: true` gets us `resolve_runtime()`
    // — `cmd::start` needs `paths.pidfile()` and `paths.unix_socket()`
    // both for the already-running check (`CtlSocket::connect`) and
    // to pass `--pidfile`/`--socket` explicitly to the spawned tincd.
    CmdEntry {
        name: "start",
        needs_daemon: true,
        run: cmd_start,
        help: "start [tincd OPTIONS]  Start tincd.",
    },
    CmdEntry {
        name: "restart",
        needs_daemon: true,
        run: cmd_restart,
        help: "restart [tincd OPTIONS]  Restart tincd.",
    },
    CmdEntry {
        name: "pid",
        needs_daemon: true,
        run: cmd_pid,
        help: "pid                    Show PID of currently running tincd.",
    },
    CmdEntry {
        name: "stop",
        needs_daemon: true,
        run: cmd_stop,
        help: "stop                   Stop tincd.",
    },
    CmdEntry {
        name: "reload",
        needs_daemon: true,
        run: cmd_reload,
        help: "reload                 Partially reload configuration of running tincd.",
    },
    CmdEntry {
        name: "retry",
        needs_daemon: true,
        run: cmd_retry,
        help: "retry                  Retry all outgoing connections.",
    },
    CmdEntry {
        name: "purge",
        needs_daemon: true,
        run: cmd_purge,
        help: "purge                  Purge unreachable nodes.",
    },
    CmdEntry {
        name: "debug",
        needs_daemon: true,
        run: cmd_debug,
        help: "debug [N]              Show or set debug level.",
    },
    CmdEntry {
        name: "disconnect",
        needs_daemon: true,
        run: cmd_disconnect,
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
        run: cmd_get,
        help: "get VARIABLE           Print current value of VARIABLE",
    },
    CmdEntry {
        name: "set",
        needs_daemon: true,
        run: cmd_set,
        help: "set VARIABLE VALUE     Set VARIABLE to VALUE",
    },
    CmdEntry {
        name: "add",
        needs_daemon: true,
        run: cmd_add,
        help: "add VARIABLE VALUE     Add VARIABLE with the given VALUE",
    },
    CmdEntry {
        name: "del",
        needs_daemon: true,
        run: cmd_del,
        help: "del VARIABLE [VALUE]   Remove VARIABLE [only ones with matching VALUE]",
    },
    // The `config` umbrella: `tinc config get Port` ≡ `tinc get
    // Port`. Upstream's `ctl=true` on this one is the exception
    // that proves the rule — they remembered for `config` and
    // forgot for the aliases.
    CmdEntry {
        name: "config",
        needs_daemon: true,
        run: cmd_config_umbrella,
        // No help line for `config` — it's a verbosity nobody
        // types. The aliases are the user-facing names.
        help: "",
    },
    // ─── dump: nodes/edges/subnets/connections/graph/invitations
    // `dump` and `list` both → cmd_dump.
    //
    // `needs_daemon: true` even though `dump invitations` is pure
    // readdir. Upstream has `ctl=false` and connects INSIDE cmd_dump after the kind switch. We can't — our adapter
    // gets immutable `&Paths`, and `CtlSocket::connect` needs the
    // resolved `pidfile()`, and `resolve_runtime` is `&mut`. So:
    // resolve unconditionally. `dump invitations` pays one harmless
    // `access(2)` probe and never calls `pidfile()`. The probe-free
    // principle ("init doesn't stat /var/run") trades against the
    // signature-churn cost; one stat for a rare subcommand is fine.
    //
    // The alternative (`dump-invitations` as a separate top-level
    // verb) would change the C's argv shape. Don't.
    CmdEntry {
        name: "dump",
        needs_daemon: true,
        run: cmd_dump,
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
        run: cmd_dump,
        help: "",
    },
    // ─── info: node summary or route lookup
    // Unlike `dump`'s `ctl=false`, info has `ctl=true` — it ALWAYS hits
    // the daemon (no readdir-only path). So `needs_daemon: true`
    // is exact, not a compromise.
    CmdEntry {
        name: "info",
        needs_daemon: true,
        run: cmd_info,
        help: "info NODE|SUBNET|ADDRESS    Give information about a particular NODE, SUBNET or ADDRESS.",
    },
    // ─── top: real-time per-node traffic
    // The `ctl=false` means "don't pre-connect_tincd" — cmd_top
    // calls connect itself. Same here: `needs_daemon: true` makes main() resolve the pidfile path
    // (which `top::run` needs) but doesn't connect; `top::run`
    // connects.
    //
    // The `#ifdef HAVE_CURSES` else-branch prints "compiled without
    // curses support"; we always have it (tui.rs is always built on
    // Unix).
    CmdEntry {
        name: "top",
        needs_daemon: true,
        run: cmd_top,
        help: "top                         Show real-time statistics",
    },
    // ─── log: stream daemon's logger() output
    // `ctl=false`: "don't pre-connect" (cmd_log connects itself).
    // Same as `top`: `needs_daemon: true` resolves the pidfile path
    // (the connect needs it), but doesn't connect.
    //
    // Runs forever; Ctrl-C to stop.
    CmdEntry {
        name: "log",
        needs_daemon: true,
        run: cmd_log,
        help: "log [level]                 Dump log output [up to the specified level]",
    },
    // ─── pcap: stream packet capture
    // Same self-connect pattern. `tinc pcap | wireshark -k -i -` is the
    // use case.
    CmdEntry {
        name: "pcap",
        needs_daemon: true,
        run: cmd_pcap,
        help: "pcap [snaplen]              Dump traffic in pcap format [up to snaplen bytes per packet]",
    },
    // ─── edit: spawn $EDITOR on a config file, then reload
    // `ctl=false`: "doesn't need pre-connect" — the reload AFTER edit is
    // best-effort. We set `needs_daemon: true` anyway so the
    // pidfile path gets resolved (the silent reload needs it).
    // The connect-can-fail is INSIDE cmd::edit::run.
    //
    // Undocumented upstream (no `edit` line in the usage block).
    // We list it; it's useful.
    CmdEntry {
        name: "edit",
        needs_daemon: true,
        run: cmd_edit,
        help: "edit FILE                   Edit a config file with $VISUAL/$EDITOR/vi",
    },
    // ─── version, help: trivial dispatchers
    // `tinc help` ≡ `tinc --help`, `tinc version` ≡ `tinc --version`.
    // Both ignore args (well, version checks `argc > 1`).
    //
    // `needs_daemon: false` — these need NOTHING. The Paths is
    // resolved unconditionally by main but unused.
    //
    // Help text is empty: listing `help` in `--help`'s output is
    // recursive; the user already found it. The C lists neither
    // (no `version`/`help` lines in the usage block). Our `help:
    // ""` makes the --help printer skip them.
    CmdEntry {
        name: "version",
        needs_daemon: false,
        run: cmd_version,
        help: "",
    },
    CmdEntry {
        name: "help",
        needs_daemon: false,
        run: cmd_help,
        help: "",
    },
    // ─── network: list networks under confdir
    // Upstream has TWO modes (list / switch); we only have list. The
    // switch is C-behavior-drop #2 — only useful in the readline
    // loop, which we don't have. `tinc network NAME` errors with
    // "use -n NAME" advice.
    //
    // `needs_daemon: false` — just reads the filesystem. No
    // daemon, no socket, no pidfile.
    //
    // We drop the switch half from the help too.
    CmdEntry {
        name: "network",
        needs_daemon: false,
        run: cmd_network,
        help: "network                List all known networks (to switch, use -n NETNAME)",
    },
];

/// Arity guard for the many zero-arg adapters: `Err(TooManyArgs)` if
/// anything was passed, else `Ok(())`. Keeps the per-command wrappers
/// to a single line instead of repeating the same three-line check a
/// dozen times.
fn no_args(args: &[String]) -> Result<(), CmdError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(CmdError::TooManyArgs)
    }
}

/// Thin adapter: `&[String]` argv → typed args for `cmd::init::run`.
/// Each command has one of these; it's where arity errors live.
///
/// Upstream does `if(argc > 2)` / `if(argc < 2)` inline. We do it
/// here so `cmd::init::run` gets a nice `&str` and never sees argv.
fn cmd_init(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    use std::io::{IsTerminal, Read};
    match args {
        [name] => cmd::init::run(paths, name),
        [] => {
            // C `cmd_init` prompts on a tty or reads one line from
            // stdin. We don't prompt (no interactive mode), but we DO
            // accept the piped form so `echo NAME | tinc -c X init`
            // scripts written for C tinc keep working — same as
            // `cmd_join` already does for the invitation URL.
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
#[allow(clippy::unnecessary_wraps)] // dispatch table contract: all entries return Result
fn cmd_genkey_rsa_stub(_: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    if args.len() > 1 {
        return Err(CmdError::TooManyArgs);
    }
    eprintln!(
        "Warning: this tinc was built without legacy protocol support; skipping RSA key generation."
    );
    Ok(())
}

/// `cmd_generate_ed25519_keys`: zero args.
fn cmd_genkey(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::genkey::run(paths)
}

/// `cmd_sign`: optional file arg.
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
    // clock is set before 1970. `time(NULL)` would return
    // `(time_t)-1` on the same system (and then `%ld` formats it as
    // `-1`, and `verify`'s `!t` check passes — a different bug). We
    // crash. Better.
    #[allow(clippy::cast_possible_wrap)] // unix time fits i64 until year 292e9
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;
    cmd::sign::sign(paths, input, t, std::io::stdout().lock())
}

/// `cmd_fsck`: zero args.
///
/// fsck never `Err`s — its job is to report errors, not propagate.
/// `Report::ok` maps to exit code. The `Err` arm here only fires if
/// `cmd::fsck::run` itself panics-via-?, which it doesn't.
///
/// `cmd_prefix` reconstruction: upstream does this by reading
/// `confbasegiven`/`netname` globals. We
/// reconstruct it from `Paths` — we don't have the globals, but we
/// know `confbase` is always set, so `tinc -c CONFBASE` is the
/// canonical form. Slightly less pretty than the C (which would say
/// `tinc -n NETNAME` if you used `-n`), but always correct.
fn cmd_fsck(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    use cmd::fsck::Severity;

    no_args(args)?;

    // The argv[0] becomes `exe_name` for the suggestion messages.
    // We hardcode `tinc` — there's only one binary name. (Upstream
    // cares because of legacy:
    // `tincctl` was once a separate binary.)
    let cmd_prefix = format!("tinc -c {}", paths.confbase.display());

    let report = cmd::fsck::run(paths, g.force)?;

    // ERROR: / WARNING: prefixes.
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

/// `cmd_invite`: one required arg (the new node's name).
///
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
        // Phrasing matches upstream so users grepping forums find
        // the right post.
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

// Daemon-RPC adapters — the simple control commands
//
// Each is: arity check → `cmd::ctl_simple::*`. The arity check is
// the only thing the adapter adds; everything else (connect, send,
// ack) is in the lib function. Same pattern as the filesystem-
// command adapters.

/// `cmd_pid`: zero args. Prints daemon's pid + newline.
fn cmd_pid(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    let pid = cmd::ctl_simple::pid(paths)?;
    // Stdout, newline.
    println!("{pid}");
    Ok(())
}

/// `cmd_start`: any number of args, all passed through to tincd.
/// Everything after `start` becomes a tincd arg. `tinc start -d 5` → `tincd -c … --pidfile … --socket … -d 5`.
#[cfg(unix)]
fn cmd_start(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    cmd::start::start(paths, args)
}

/// `cmd_restart`: stop (best-effort), then start.
#[cfg(unix)]
fn cmd_restart(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    cmd::start::restart(paths, args)
}

/// `cmd_stop`: zero args. Stops daemon, drains until socket closes.
fn cmd_stop(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::ctl_simple::stop(paths)
}

/// `cmd_reload`: zero args.
fn cmd_reload(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::ctl_simple::reload(paths)
}

/// `cmd_retry`: zero args.
fn cmd_retry(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::ctl_simple::retry(paths)
}

/// `cmd_purge`: zero args.
fn cmd_purge(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::ctl_simple::purge(paths)
}

/// `cmd_debug`: exactly one arg (the level). Upstream:
/// `if(argc != 2)` — not optional, must be given. We extend: no arg
/// queries the current level (sends -1, daemon returns current
/// without changing). Upstream doesn't expose this but the daemon
/// supports it (`if(new_level >= 0)`).
fn cmd_debug(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    let level = match args {
        // Our extension: query mode.
        [] => -1,
        [lvl] => lvl
            .parse()
            .map_err(|_| CmdError::BadInput(format!("Invalid debug level {lvl:?}.")))?,
        _ => return Err(CmdError::TooManyArgs),
    };
    let prev = cmd::ctl_simple::debug(paths, level)?;
    // `"Old level %d, new level %d.\n"` to stderr (yes, stderr).
    // We match. The query mode prints just the
    // level (it's the answer to the question, goes to stdout).
    if level < 0 {
        println!("{prev}");
    } else {
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
    // ─── Arity
    // `if(argc < 2)` after the verb peel. "2" because argv includes
    // argv[0]; ours doesn't, so "1".
    if args.is_empty() {
        return Err(CmdError::BadInput("Invalid number of arguments.".into()));
    }

    // ─── Join the rest
    // `strncat` loop with single space. `tinc set Name foo bar` → `"Name foo bar"` → var=Name,
    // val="foo bar". The space-join recreates the user's intent
    // (modulo collapsing multiple shell-quoted spaces, but the
    // C has the same loss).
    let joined = args.join(" ");

    // ─── Run
    let (out, warnings) = cmd::config::run(paths, action, &joined, g.force)?;
    config_output(paths, out, &warnings);
    Ok(())
}

/// Print the result. Factored out so the integration tests can see
/// the contract: `Got` → stdout one-per-line, `Edited` → reload.
fn config_output(paths: &Paths, out: cmd::config::ConfigOutput, warnings: &[cmd::config::Warning]) {
    use cmd::config::ConfigOutput;

    // ─── Print warnings to stderr
    // We collect-then-print.
    for w in warnings {
        eprintln!("{w}");
    }

    // ─── Handle output
    match out {
        ConfigOutput::Got(values) => {
            // One per line, stdout.
            for v in values {
                println!("{v}");
            }
        }
        ConfigOutput::Edited(result) => {
            // `if(connect_tincd(false)) sendline(REQ_RELOAD)`.
            // Best-effort. The `false` means "don't error if the
            // daemon's down". We swallow the entire Result —
            // daemon down? fine. daemon up but reload failed?
            // also fine, the file's already written, the daemon
            // will pick it up on next start. The C doesn't check
            // the ack either.
            if result.changed {
                let _ = cmd::ctl_simple::reload(paths);
            }
        }
    }
}

// ─── The four toplevel adapters
// C uses ONE function and an `argv--` shift to re-read the command
// name. We can't see argv[0] (dispatch ate it), so each toplevel
// name passes its action explicitly. Four 1-line wrappers; the
// alternative (threading argv[0] through Globals) is uglier.
//
// The first cut of this had ONE adapter that re-parsed args[0] for
// the verb. That worked for get/set by accident (get→GET default;
// set→GET→coerced to SET via get-with-value) but `tinc add
// ConnectTo bob` would have routed GET→SET, *deleting* other
// ConnectTo lines instead of appending. Caught by reading the
// fall-through case carefully before building. Separate adapters.

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

/// `tinc config <verb> ...`. The umbrella form. The
/// `if(strcasecmp(argv[0], "config"))` test DOESN'T shift — so
/// argv[1] is already the verb to peel.
///
/// `tinc config Port` (no verb) → default GET: `action = GET` is
/// the init, overwritten only on verb match.
///
/// `replace` and `change` are aliases for `set`. Only available
/// here, not as toplevel commands — same as upstream.
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

/// `cmd_disconnect`: exactly one arg (node name).
fn cmd_disconnect(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    match args {
        [] => Err(CmdError::MissingArg("node name")),
        [name] => cmd::ctl_simple::disconnect(paths, name),
        _ => Err(CmdError::TooManyArgs),
    }
}

/// `cmd_dump`: argv[1] is the kind.
///
/// Two-stage dispatch: argv → `Kind` (the `reachable` shift dance),
/// then `Kind` → connect-or-readdir. The C does it as one function
/// with `if(strcasecmp(argv[1], "invitations")) return dump_invitations()`
/// at the top — same shape here. The kind-parse is in lib code so
/// it's testable without spawning the binary.
///
/// Output goes to stdout line-by-line. For an empty dump (zero rows)
/// the C is silent (exit 0, no output); for `dump invitations` with
/// no invitations upstream writes `"No outstanding invitations."`
/// to STDERR. The stderr-not-stdout choice is
/// a hint: scripts parsing `tinc dump invitations | while read` don't
/// want a non-data line. We match.
fn cmd_dump(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    use cmd::dump::{DumpOutput, Kind, dump, dump_invitations, parse_kind};

    // ─── argv → Kind
    // The arity errors and `Unknown dump type` live in here.
    let kind = parse_kind(args)?;

    // ─── Invitations: pure readdir, no daemon
    // BEFORE `connect_tincd`. Works daemon-down. (We did pay one `access(2)` for `resolve_runtime`
    // — see the table-entry comment.)
    if kind == Kind::Invitations {
        let rows = dump_invitations(paths)?;
        if rows.is_empty() {
            // stderr, exit 0. Upstream has a typo (`"Cannot not
            // read"`) on the EACCES path but not on the empty path;
            // we don't replicate the typo.
            eprintln!("No outstanding invitations.");
        } else {
            // `printf("%s %s\n", filename, name)`. Space-separated,
            // one per line.
            for r in rows {
                println!("{} {}", r.cookie_hash, r.invitee);
            }
        }
        return Ok(());
    }

    // ─── Daemon-backed: connect, send, recv, format
    let DumpOutput::Lines(lines) = dump(paths, kind)?;
    for line in lines {
        println!("{line}");
    }
    // Empty dump → silent. C: zero-iteration while loop, return 0.
    Ok(())
}

/// `cmd_info`: one arg (node name OR subnet OR address).
///
/// Bimodal output: node → one big block; subnet → zero-to-many
/// `Subnet:/Owner:` pairs. The lib code returns `InfoOutput`; we
/// route to print here.
fn cmd_info(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    use cmd::info::{InfoOutput, info};

    // Exactly one positional.
    let item = match args {
        [] => return Err(CmdError::MissingArg("node name, subnet, or address")),
        [item] => item,
        _ => return Err(CmdError::TooManyArgs),
    };

    match info(paths, item)? {
        // Node mode: ready-to-print, trailing newline included
        // (NodeInfo::format ends every line with `\n`). `print!`
        // not `println!` to avoid a double-newline at the end.
        InfoOutput::Node(s) => {
            print!("{s}");
        }
        // Subnet mode: per-match block. Two spaces after `Owner:`
        // (column alignment with `Subnet:`).
        InfoOutput::Subnet(matches) => {
            for m in matches {
                println!("Subnet: {}", m.subnet);
                println!("Owner:  {}", m.owner);
            }
        }
    }
    Ok(())
}

/// `cmd_top`: zero args. The TUI loop.
///
/// Unlike every other command, this one DOESN'T return until the
/// user quits ('q') or the daemon dies. The `Result` return is for
/// connect failures ("daemon not running") and the `RawMode::enter`
/// stdin-not-a-tty case (`tinc top </dev/null`). Mid-session daemon
/// death is `Ok(())` — silent exit, same as upstream.
///
/// `g.netname` for the row-0 header (`netname ? netname : ""`).
/// This is the FIRST adapter to use Globals — the others take
/// `_: &Globals`. (`cmd_invite` uses it too, for
/// the URL fragment, but that's a Paths concern; this is pure
/// display.)
fn cmd_top(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::top::run(paths, g.netname.as_deref())
}

/// `cmd_log`: optional level arg.
///
/// `tinc log` → daemon's level. `tinc log 5` → filter at 5.
/// Runs until Ctrl-C (kills process, exit 130) or daemon dies
/// (clean exit 0).
///
/// Upstream's `atoi(argv[1])` accepts garbage → 0; we error.
fn cmd_log(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    let level = match args {
        [] => None,
        // `parse::<i32>()` rejects garbage. C's `atoi` doesn't
        // (returns 0). The change is observable only for invalid
        // input — `tinc log abc` errors instead of silently using
        // level 0. Better.
        [lvl] => Some(
            lvl.parse::<i32>()
                .map_err(|_| CmdError::BadInput(format!("Invalid debug level: {lvl}")))?,
        ),
        _ => return Err(CmdError::TooManyArgs),
    };
    cmd::stream::run_log(paths, level)
}

/// `cmd_pcap`: optional snaplen arg.
///
/// `tinc pcap` → full packets. `tinc pcap 96` → first 96 bytes
/// (headers only, less throughput). The 0 default means "daemon
/// don't clip" (the router checks truthy).
///
/// `parse::<u32>()` rejects negative — `atoi("-5")` would
/// be `-5` then implicit-cast to a `uint32_t` arg, becoming a
/// huge number, daemon never clips. `tinc pcap -5` failing is
/// better than silently capturing 4GiB packets.
fn cmd_pcap(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    let snaplen = match args {
        [] => 0,
        [s] => s
            .parse::<u32>()
            .map_err(|_| CmdError::BadInput(format!("Invalid snaplen: {s}")))?,
        _ => return Err(CmdError::TooManyArgs),
    };
    cmd::stream::run_pcap(paths, snaplen)
}

/// `cmd_edit`: shorthand resolves to confbase or hosts/, spawn
/// editor, silent reload.
///
/// `tinc edit tinc.conf` → `vi /etc/tinc/.../tinc.conf`.
/// `tinc edit alice` → `vi /etc/tinc/.../hosts/alice`.
///
/// Exactly one arg.
fn cmd_edit(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    let [file] = args else {
        // Same message for 0 and 2+.
        return Err(CmdError::BadInput("Invalid number of arguments.".into()));
    };
    cmd::edit::run(paths, file)
}

/// `cmd_version`: print and exit. `argc > 1` is `TooManyArgs`.
/// The print itself is `print_version()`
/// from this binary — same fn `--version` calls.
fn cmd_version(_: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    print_version();
    Ok(())
}

/// `cmd_help`: print and exit. Upstream IGNORES args (`(void)argc; (void)argv`); `tinc help foo` is
/// the same as `tinc help`. Match it. (Per-subcommand help would
/// be nice but the C doesn't have it; YAGNI.)
///
/// `clippy::unnecessary_wraps`: the dispatch table needs `fn(
/// &Paths, &Globals, &[String]) -> Result<_,_>`. Can't return
/// `()`. The wrap IS the table contract.
#[allow(clippy::unnecessary_wraps)] // dispatch table contract: all entries return Result
fn cmd_help(_: &Paths, _: &Globals, _: &[String]) -> Result<(), CmdError> {
    print_help();
    Ok(())
}

/// `cmd_network`: list or (rejected) switch.
///
/// `tinc network` → list. `tinc network NAME` → "use -n NAME"
/// error. `tinc network a b` → too many.
fn cmd_network(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    let arg = match args {
        [] => None,
        [name] => Some(name.as_str()),
        _ => return Err(CmdError::TooManyArgs),
    };
    cmd::network::run(paths, arg)
}

/// `cmd_join`: one arg (the URL) or zero (read URL from stdin).
///
/// Upstream also accepts `tinc join` with no arg + tty prompt. We
/// support stdin read (so `echo URL | tinc -c CONF join` works)
/// but no tty prompt — same "no prompts" deviation as elsewhere.
/// `--force` propagates to `finalize_join`'s `VAR_SAFE` override.
fn cmd_join(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    use std::io::Read;

    let url_buf;
    let url: &str = match args {
        [u] => u,
        [] => {
            // `if(tty) prompt; fgets(line, ..., stdin); rstrip(line);`.
            // We always read from stdin (no tty check). One line,
            // strip trailing newline. Same as `tinc import` does
            // for its blob.
            //
            // `read_to_string` not `BufRead::read_line` — the URL
            // is the only thing on stdin, slurp it. Trim trailing
            // ws (including \r\n on Windows).
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

/// `cmd_verify`: required signer arg, optional file arg.
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
    no_args(args)?;
    // `lock()` for the BufWriter; export does many small writes.
    cmd::exchange::export(paths, std::io::stdout().lock())
}

/// `cmd_export_all`: zero args, write to stdout.
fn cmd_export_all(paths: &Paths, _: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    cmd::exchange::export_all(paths, std::io::stdout().lock())
}

/// `cmd_import`: zero args, read from stdin. Maps count→exit-code:
/// returns 1 if zero imported.
fn cmd_import(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    no_args(args)?;
    let count = cmd::exchange::import(paths, std::io::stdin().lock(), g.force)?;
    if count > 0 {
        eprintln!("Imported {count} host configuration files.");
        Ok(())
    } else {
        // We surface as BadInput so the dispatcher prints + exits 1. Same effect.
        Err(CmdError::BadInput(
            "No host configuration files imported.".into(),
        ))
    }
}

/// `cmd_exchange`: export, then import.
///
/// Upstream is `return cmd_export(...) ? 1 : cmd_import(...)`. Short-
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

/// `cmd_exchange_all`: export-all, then import.
fn cmd_exchange_all(paths: &Paths, g: &Globals, args: &[String]) -> Result<(), CmdError> {
    cmd_export_all(paths, g, args)?;
    cmd_import(paths, g, args)
}

/// `parse_options` + the env-var fallback.
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
    // netname is filled in main() after `.` → None normalization.
    // parse_global_options only knows the raw `-n` value, not the
    // normalized one. Separating concerns: this fn parses argv,
    // main() applies the netname rules (env fallback, `.` sentinel,
    // traversal guard) and *then* captures it into Globals.
    let mut globals = Globals {
        force: false,
        netname: None,
    };
    let mut rest = Vec::new();

    // `getopt_long(argc, argv, "+bc:n:", ...)` — the `+` means stop
    // at first non-option. We loop until we hit something that doesn't
    // start with `-`, then dump everything remaining into `rest`.
    //
    // No bundled short flags here (`-cn` doesn't mean `-c -n`) because
    // both `-c` and `-n` take arguments. Short-with-arg can be `-cFOO`
    // or `-c FOO` in getopt; we accept both — C `getopt_long` does,
    // and `-c-n` unambiguously means `-c` with arg `-n` under getopt
    // semantics (the option takes a required argument, so the rest of
    // the token IS the argument).
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
            s if s.starts_with("-c") && s.len() > 2 => {
                input.confbase = Some(PathBuf::from(&s[2..]));
            }
            "-n" | "--net" => {
                let val = args.next().ok_or("option -n requires an argument")?;
                input.netname = Some(val);
            }
            s if s.starts_with("--net=") => {
                input.netname = Some(s["--net=".len()..].to_owned());
            }
            s if s.starts_with("-n") && s.len() > 2 => {
                input.netname = Some(s[2..].to_owned());
            }
            // `-h` alias. tincd accepts it; keeping the two binaries
            // consistent is cheaper than explaining why one does and
            // the other doesn't.
            "-h" | "--help" => {
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
            // `--pidfile=FILE`. Overrides the /var/run ↔ confbase resolution dance entirely. Only
            // matters for daemon-RPC commands. No short form (C: long-only).
            "--pidfile" => {
                let val = args.next().ok_or("option --pidfile requires an argument")?;
                input.pidfile = Some(PathBuf::from(val));
            }
            s if s.starts_with("--pidfile=") => {
                input.pidfile = Some(PathBuf::from(&s["--pidfile=".len()..]));
            }
            // `OPT_BATCH` sets `tty = false` — disables interactive
            // prompts. We have no prompts (see `cmd/init.rs` doc), so
            // -b is a no-op. Accept-and-ignore for compat with scripts
            // that pass it.
            "-b" | "--batch" => {}
            // `--force`. No short form — the long-only OPT_FORCE doesn't map to a single char.
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

    // ─── NETNAME env fallback
    // Only if -n wasn't given. Standard
    // env-under-flag precedence.
    if input.netname.is_none()
        && let Ok(env_net) = env::var("NETNAME")
    {
        input.netname = Some(env_net);
    }

    // ─── netname "." → None
    // "." is the "top-level" sentinel — it
    // means "no netname, use confdir as confbase". Allows `NETNAME=.`
    // in your env to explicitly say "I want /etc/tinc not
    // /etc/tinc/$NETNAME". Also the empty string (which you can't
    // pass with `-n` but can set in env: `NETNAME=`).
    if matches!(input.netname.as_deref(), Some("" | ".")) {
        input.netname = None;
    }

    // ─── netname path-traversal guard
    // `strpbrk(netname, "\\/") || *netname == '.'`. Netname becomes a path component; slashes would escape confdir.
    // Leading dot rejects `..` (`strpbrk` doesn't catch `..` but `*=='.'`
    // does — and also rejects `.hidden`, which is fine, nobody names
    // their VPN `.git`).
    //
    // This is a *weaker* check than `check_id` — netname allows `-`,
    // for instance. The C is permissive here on purpose; netname is a
    // local filesystem thing, not a wire protocol token.
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

    // The C help text is ~40 lines covering every command. We only
    // have one. Generate from COMMANDS so adding an entry adds it to
    // help automatically.
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
        // `config` has empty help (it's the umbrella nobody types).
        // Same skip-on-empty as upstream's `if(commands[i].help)`.
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
            // `if(optind >= argc) return cmd_shell(...)` — bare
            // `tinc` enters interactive shell mode. We don't have
            // shell mode. Print help, exit 1. Matches what
            // `git` does for bare `git`.
            eprintln!("No command given.");
            eprintln!("Try `tinc --help' for more information.");
            return ExitCode::FAILURE;
        }
        Some(_) => {}
    }

    let cmd_name = &rest[0];
    let cmd_args = &rest[1..];

    // ─── Dispatch
    // Linear scan of `commands[]` with `strcasecmp`. We use
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
    //
    // `globals.netname` is captured *before* `for_cli` because
    // `for_cli` borrows `input` and we'd otherwise need a clone.
    // (Not strictly necessary — `for_cli` takes `&input` — but
    // keeping the clone explicit makes the data flow obvious.)
    let globals = Globals {
        netname: input.netname.clone(),
        ..globals
    };
    let mut paths = Paths::for_cli(&input);

    // Daemon-RPC commands need pidfile/socket resolved. The probe
    // touches the fs (`access(2)` on `/var/run/tinc.X.pid`) so we
    // only do it for commands that need it. Filesystem commands
    // stay probe-free — `tinc init` doesn't `stat /var/run` for
    // no reason.
    //
    // The `&input` reborrow works because `for_cli` only borrows;
    // `resolve_runtime` borrows again. (If for_cli consumed, we'd
    // need `input.clone()` here.)
    if entry.needs_daemon {
        paths.resolve_runtime(&input);
    }

    match (entry.run)(&paths, &globals, cmd_args) {
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
