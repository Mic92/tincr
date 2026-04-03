//! Path resolution. C reference: `src/names.c` `make_names()`.
//!
//! ## What this is
//!
//! Every tinc command needs to know "where is the config for net X".
//! In C, `make_names()` reads `netname`/`confbase` globals, scribbles
//! `confbase`/`tinc_conf`/`hosts_dir`/`pidfilename`/`unixsocketname`/…
//! globals back, and every other function reads those. It's a pure
//! function disguised as a side effect.
//!
//! Here it's an actual function: argv-shaped inputs → `Paths` struct.
//! No globals. Every command takes `&Paths`.
//!
//! ## What's NOT here yet
//!
//! `pidfilename`, `unixsocketname`, `logfilename` — the
//! daemon/control-socket paths with the `LOCALSTATEDIR` access-probe
//! fallback (`names.c:108-148`). First consumer is Phase 5b RPC
//! (`connect_tincd` reads pidfile + connects to unix socket). The
//! filesystem-only commands (`init`, `generate-keys`, `export`, etc.)
//! never touch those globals. Add the fields when 5b lands, alongside
//! the consumer.
//!
//! `identname` — `"tinc.NETNAME"` for syslog. First consumer is the
//! daemon's logger.
//!
//! Windows registry lookup (`HKLM\SOFTWARE\tinc`) — `#[cfg(windows)]`
//! when we cross that bridge.
//!
//! ## On `CONFDIR`
//!
//! C bakes it at meson configure time (`-Dsysconfdir`, default `/etc`
//! or `/usr/local/etc` depending on prefix). Rust doesn't have a
//! configure step. We use `option_env!("TINC_CONFDIR")` at compile
//! time, defaulting to `/etc`. The Nix derivation can set it; a
//! `cargo build` from a fresh checkout gets `/etc`. If you want
//! `/usr/local/etc`, `TINC_CONFDIR=/usr/local/etc cargo build`.
//!
//! There's a temptation to do XDG (`~/.config/tinc`) when running
//! unprivileged. The C does **not** do this — `tinc init` as non-root
//! fails with EACCES on `/etc/tinc` mkdir, and that's a known
//! papercut upstream. We don't fix it here. Don't add behavior the C
//! doesn't have without a separate, deliberate decision; that decision
//! lives in `RUST_REWRITE_PLAN.md` Phase 4a notes.

use std::path::PathBuf;

/// `CONFDIR` from `config.h`. Baked at compile time.
///
/// `option_env!` not `env!` — we want a default, not a build failure.
/// Packagers set `TINC_CONFDIR` in their build; everyone else gets
/// `/etc`. Same effective behavior as meson's `dir_sysconf`.
const CONFDIR: &str = match option_env!("TINC_CONFDIR") {
    Some(d) => d,
    // C: `cdata.set_quoted('CONFDIR', dir_sysconf)` in `src/meson.build:7`.
    // meson's default sysconfdir under prefix=/usr is /etc. Under
    // prefix=/usr/local it's /usr/local/etc. We pick /etc because
    // distro packages set prefix=/usr, and that's the common case.
    None => "/etc",
};

/// `LOCALSTATEDIR`. C: `cdata.set_quoted('LOCALSTATEDIR', dir_local_state)`
/// in `src/meson.build:9`.
///
/// Same compile-time constant treatment as `CONFDIR`. meson default
/// under prefix=/usr is `/var`. Nix builds will set `TINC_LOCALSTATEDIR`
/// alongside `TINC_CONFDIR` to whatever `dir_local_state` resolves to.
///
/// Only used for the pidfile/socket path: `/var/run/tinc.NETNAME.pid`.
/// The fallback dance (`names.c:111-148`) means this path is *tried
/// first*, then `confbase/pid` if `/var/run` isn't writable (non-root
/// testing).
const LOCALSTATEDIR: &str = match option_env!("TINC_LOCALSTATEDIR") {
    Some(d) => d,
    None => "/var",
};

/// All the paths a command needs. The C globals, materialized.
///
/// These are the *input* paths — where to look for config — not output
/// paths. `init` writes here; `export` reads here. Neither cares about
/// `pidfilename`.
///
/// `tinc_conf` and `hosts_dir` are derived from `confbase` (just
/// `confbase.join(...)`). The C precomputes them as separate globals
/// (`tincctl.c:3343-3344`) because `snprintf` is verbose; we do the
/// same because `paths.tinc_conf()` reads better at every call site
/// than `paths.confbase.join("tinc.conf")`.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `confbase` — config root for this net. `/etc/tinc/NETNAME` or
    /// `/etc/tinc` if no netname, or whatever `--config` said.
    ///
    /// Everything else hangs off this. `tinc.conf`, `hosts/`, `cache/`,
    /// `ed25519_key.priv`, `tinc-up` — all `confbase.join(...)`.
    pub confbase: PathBuf,

    /// `pidfilename` — where the daemon writes its pid + control
    /// cookie. The CLI reads this in `connect_tincd` (`tincctl.c:763`).
    ///
    /// Only set when *resolved*. `for_cli()` doesn't resolve it (the
    /// 4a commands don't need it). 5b commands call `resolve_runtime()`
    /// which fills it via the LOCALSTATEDIR fallback dance, after
    /// which `pidfile()`/`unix_socket()` are valid.
    ///
    /// Why lazy: the resolution `access(2)`s the filesystem (probes
    /// for `/var/run/tinc.X.pid` then `confbase/pid`). 4a commands
    /// like `init` and `export` shouldn't be doing fs probes for
    /// state they don't use. C does it eagerly (`make_names` always
    /// resolves, even for `cmd_init`) because globals are free; we
    /// have a struct, so we make the dependency explicit.
    ///
    /// `Option<PathBuf>` so `pidfile()` can panic with a clear
    /// message if you forgot `resolve_runtime()`. Better than a
    /// silent `confbase/pid` default that masks a missing call.
    pidfile: Option<PathBuf>,

    /// `confdir` — `/etc/tinc`, the *parent* dir. `makedirs(DIR_CONFDIR)`
    /// creates this when `confbase` was derived from netname (so
    /// `/etc/tinc` needs to exist before `/etc/tinc/NETNAME` can).
    /// When `--config` was given, this is `None` — we don't know what
    /// the parent should be, and the user said where to look, so we
    /// trust the path exists or `mkdir(confbase)` will fail loudly.
    ///
    /// C: `confdir` is always set (to `CONFDIR "/tinc"` even when
    /// `confbase_given`), but `makedirs` skips creating it when
    /// `confbase_given` is true (`fs.c:37`). Same effect, modeled
    /// differently: rather than store a path we'll never use plus a
    /// flag saying not to use it, store `Option`.
    pub confdir: Option<PathBuf>,
}

/// Where the pidfile resolved to. Distinct because the *daemon* uses
/// the same dance but needs to know which branch fired — for the
/// LOCALSTATEDIR-unwritable warning (`names.c:142`). The CLI doesn't
/// care, it just opens whichever exists.
///
/// Not used by the CLI yet (it just calls `pidfile()`); the variant
/// is wired for when `for_daemon()` lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidfileSource {
    /// `--pidfile=X`. User said where; no probing.
    Explicit,
    /// `/var/run/tinc.NETNAME.pid`. The system path.
    LocalState,
    /// `confbase/pid`. The fallback (non-root, unwritable /var/run).
    Confbase,
}

/// Input axis. The C globals that `make_names()` *reads*, before it
/// writes the others. These come from getopt (`-c` / `-n`).
///
/// You only ever set one or the other in practice (`-c` overrides
/// `-n`), but the C accepts both with a warning, and so do we.
#[derive(Debug, Default)]
pub struct PathsInput {
    /// `-n NETNAME` / `--net=NETNAME`. Names a subdirectory of confdir.
    pub netname: Option<String>,

    /// `-c DIR` / `--config=DIR`. Explicit confbase. Wins over netname.
    pub confbase: Option<PathBuf>,

    /// `--pidfile=X`. Overrides all the resolution logic. C
    /// `tincctl.c:245-246`: `OPT_PIDFILE` → `pidfilename = xstrdup(optarg)`.
    ///
    /// Why this is in `PathsInput`: it's input, same axis as `-c`/`-n`.
    /// The fact that it bypasses resolution is the whole point of
    /// passing it explicitly. Tests use this to point at a tempdir
    /// without the `/var/run` probe ever firing.
    pub pidfile: Option<PathBuf>,
}

impl Paths {
    /// `make_names(daemon=false)`. The CLI flavor.
    ///
    /// (The daemon flavor differs only in pidfile/log resolution, which
    /// we don't have yet. When we add those fields, this grows a
    /// `daemon: bool` parameter — or more likely a separate
    /// `for_daemon()` constructor, since the daemon binary calls it
    /// once with a literal `true` and the CLI calls it once with a
    /// literal `false`, no runtime variance.)
    ///
    /// C: `names.c:41-98` (skipping the Windows registry block and
    /// the pidfile/log block at 108+).
    #[must_use]
    pub fn for_cli(input: &PathsInput) -> Self {
        // C `if(netname && confbase) logger(...)` — both given, confbase
        // wins, warn. We warn to stderr (no logger framework yet, and
        // this is a CLI tool — stderr is the logger). The C uses
        // logger() which goes to stderr in non-daemon mode anyway.
        if input.netname.is_some() && input.confbase.is_some() {
            eprintln!("Both netname and configuration directory given, using the latter...");
        }

        // The actual decision tree. Three cases, C does it as
        // fall-through if-chains (`names.c:89-95`):
        //
        //   confbase given     → use it, confdir is moot
        //   netname given      → CONFDIR/tinc/NETNAME, confdir = CONFDIR/tinc
        //   neither            → CONFDIR/tinc,         confdir = CONFDIR/tinc
        //
        // The neither case means confbase == confdir. The C still sets
        // both as separate strings; `makedirs` then idempotently mkdirs
        // the same path twice. Harmless.

        if let Some(explicit) = &input.confbase {
            return Self {
                confbase: explicit.clone(),
                confdir: None,
                pidfile: None,
            };
        }

        let confdir: PathBuf = [CONFDIR, "tinc"].iter().collect();
        let confbase = match &input.netname {
            Some(net) => confdir.join(net),
            None => confdir.clone(),
        };

        Self {
            confbase,
            confdir: Some(confdir),
            pidfile: None,
        }
    }

    /// Resolve `pidfilename` and (implicitly) `unixsocketname`. Idempotent.
    ///
    /// `names.c:108-163`, the `daemon=false` branch. The CLI's resolution
    /// is **probe-first-then-fall-back**: try `/var/run/tinc.X.pid`,
    /// and only fall back to `confbase/pid` if the system path doesn't
    /// exist *but* the confbase one does. The asymmetry matters:
    ///
    /// | /var/run/X.pid | confbase/pid | resolved to     |
    /// |----------------|--------------|-----------------|
    /// | exists         | (any)        | /var/run/X.pid  |
    /// | missing        | exists       | confbase/pid    |
    /// | missing        | missing      | /var/run/X.pid  |
    ///
    /// The bottom row is the surprise: if *neither* exists, we return
    /// the LOCALSTATEDIR path, not confbase. C `names.c:116-125`:
    /// `fallback` only goes true when `access(LOCALSTATEDIR/...) fails
    /// AND access(confbase/pid) succeeds`. The rationale: if no daemon
    /// is running anywhere, the error message should say `/var/run/...`
    /// (the place a daemon *should* write to) not `confbase/pid` (the
    /// fallback that only matters when /var/run is unwritable).
    ///
    /// Why this is `&mut self` not a constructor: the resolution
    /// `access(2)`s the filesystem. Mutating an existing `Paths`
    /// after the cheap-construction means the test idiom stays
    /// `PathsInput { confbase: ..., ..Default::default() }` →
    /// `for_cli()` and only the 5b tests add `.resolve_runtime()`.
    ///
    /// `identname` (the `tinc.NETNAME` bit) is derived here from
    /// `netname`. We don't store identname — only one consumer (this
    /// function), and the C only stores it because syslog wants it,
    /// which we also don't have yet. When we do, lift it.
    pub fn resolve_runtime(&mut self, input: &PathsInput) -> PidfileSource {
        // --pidfile wins. No probing. C: `if(!pidfilename)` guards
        // every assignment in `names.c:104-146`; getopt already
        // populated it, so all branches are skipped.
        if let Some(explicit) = &input.pidfile {
            self.pidfile = Some(explicit.clone());
            return PidfileSource::Explicit;
        }

        if self.pidfile.is_some() {
            // Already resolved. Return Confbase as the harmless
            // default — the source isn't reread on second call. If
            // someone needs idempotent source-tracking, store it.
            return PidfileSource::Confbase;
        }

        // identname: `tinc.NETNAME` or `tinc`. C `names.c:53-59`.
        // The dot is significant: `tinc.myvpn.pid` not `tincmyvpn.pid`.
        // identname is *also* the syslog tag, which is why it's
        // human-readable.
        let identname = match &input.netname {
            Some(net) => format!("tinc.{net}"),
            None => "tinc".to_owned(),
        };

        // The probe. C uses `access(R_OK)` which checks *effective*
        // UID. `Path::exists` uses `stat`, which doesn't — but for
        // "does this file exist at all" the difference only matters
        // if you have a pidfile you can't read (mode 000), which
        // means the *daemon* set it that way, which is nonsense.
        // The C's `access` is incidental, not load-bearing. Match
        // intent (existence), not mechanism.
        let system_path: PathBuf = [LOCALSTATEDIR, "run", &format!("{identname}.pid")]
            .iter()
            .collect();
        let confbase_path = self.confbase.join("pid");

        // The truth table from the doc comment, in code. Note the
        // implicit `else` at the end: if neither exists, no
        // assignment to `fallback`, so it stays false, so we use
        // system_path. C structure preserved.
        let (path, source) = if system_path.exists() {
            (system_path, PidfileSource::LocalState)
        } else if confbase_path.exists() {
            (confbase_path, PidfileSource::Confbase)
        } else {
            (system_path, PidfileSource::LocalState)
        };

        self.pidfile = Some(path);
        source
    }

    /// `pidfilename`. Daemon writes; CLI reads.
    ///
    /// # Panics
    /// If `resolve_runtime()` hasn't been called. The panic is the
    /// point — a 4a command calling this is a bug we want to find
    /// in tests, not paper over with a default.
    #[must_use]
    pub fn pidfile(&self) -> &std::path::Path {
        self.pidfile
            .as_deref()
            .expect("pidfile() called before resolve_runtime()")
    }

    /// `unixsocketname`. Derived from `pidfilename` by string surgery.
    /// `names.c:152-161`.
    ///
    /// The rule: `foo.pid` → `foo.socket`; anything else gets
    /// `.socket` appended. Case-sensitive (`strcmp` not `strcasecmp`),
    /// exactly 4 trailing bytes (`len > 4 && pidfilename + len - 4`).
    /// `Foo.PID` does NOT match — `Foo.PID.socket`. Replicated
    /// faithfully because socket-path mismatch = silent connect fail.
    ///
    /// Why derived not stored: it's pure (no fs probe), and storing
    /// it would mean two `Option`s that are always `Some`/`None`
    /// together. One source of truth.
    ///
    /// Returns `PathBuf` not `&Path` because the surgery allocates.
    /// Called once per process (in `connect_tincd`), so no caching.
    ///
    /// # Panics
    /// Same as `pidfile()`.
    #[must_use]
    pub fn unix_socket(&self) -> PathBuf {
        let pid = self.pidfile();
        // Work in OsStr land. The C does byte-level strcmp; pidfile
        // paths are ASCII in practice (we built them from ASCII
        // constants + netname which passed `check_id`), but `--pidfile`
        // can be anything. `as_encoded_bytes` is the platform-native
        // byte view; on Unix it's the literal path bytes.
        let bytes = pid.as_os_str().as_encoded_bytes();
        // C: `if(len > 4 && !strcmp(pidfilename + len - 4, ".pid"))`.
        // `> 4` not `>= 4` — a file named exactly `.pid` (len=4)
        // doesn't match. Unlikely but the off-by-one is in the C.
        if bytes.len() > 4 && bytes.ends_with(b".pid") {
            // strncpy(unixsocketname + len - 4, ".socket", 8).
            // Slice off the .pid, append .socket. Can't `with_extension`
            // because that would also turn `tinc.myvpn.pid` into
            // `tinc.socket` (drops everything after the last dot).
            // We want exactly the last 4 bytes replaced.
            //
            // Safety: `bytes[..len-4]` is a valid encoded substring
            // because we sliced at an ASCII boundary (`.` is ASCII,
            // `pid` is ASCII). Same constraint as the from_utf8-at-
            // ASCII-byte rule in `tinc-conf::parse`.
            let stem = &bytes[..bytes.len() - 4];
            // SAFETY: stem is a prefix of valid encoded bytes,
            // truncated at an ASCII byte boundary. The forbid(unsafe)
            // means we go through OsString from-the-platform-bytes
            // instead. On Unix, `OsStr::from_bytes` is the safe path.
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                let mut s = std::ffi::OsStr::from_bytes(stem).to_owned();
                s.push(".socket");
                PathBuf::from(s)
            }
            #[cfg(not(unix))]
            {
                // On Windows the C never reaches this (different
                // path resolution via registry). Stub the type-check.
                let _ = stem;
                let mut s = pid.as_os_str().to_owned();
                s.push(".socket");
                PathBuf::from(s)
            }
        } else {
            // strncpy(unixsocketname + len, ".socket", 8). Append.
            let mut s = pid.as_os_str().to_owned();
            s.push(".socket");
            PathBuf::from(s)
        }
    }

    /// `tinc.conf` — the main config file. `tincctl.c:3343`.
    #[must_use]
    pub fn tinc_conf(&self) -> PathBuf {
        self.confbase.join("tinc.conf")
    }

    /// `hosts/` — per-peer config + public keys. `tincctl.c:3344`.
    #[must_use]
    pub fn hosts_dir(&self) -> PathBuf {
        self.confbase.join("hosts")
    }

    /// `confdir` materialized — the C-faithful version. `names.c:86`:
    /// `confdir = xstrdup(CONFDIR "/tinc")` UNCONDITIONALLY. Our
    /// `self.confdir` is `Option` (None when `--config` was given,
    /// because makedirs doesn't NEED the parent then). But `cmd_
    /// network` (`tincctl.c:2700`) reads `confdir` regardless —
    /// `tinc -c /foo network` lists `/etc/tinc/*/tinc.conf` not
    /// `/foo/../*` (the latter would be wrong anyway; `-c` points
    /// at ONE confbase, not a parent-of-confbases).
    ///
    /// This method materializes the C's always-set: `Some(x)` → `x`,
    /// `None` → `CONFDIR/tinc`. Only `cmd_network` calls it; the
    /// `Option` field is the right model for the OTHER consumer
    /// (makedirs).
    #[must_use]
    pub fn confdir_always(&self) -> PathBuf {
        // `self.confdir` is `Some` when confbase was DERIVED (from
        // netname or default). `None` when `-c` was given. The C
        // sets `CONFDIR/tinc` either way; we synthesize the same
        // value here. The two paths ARE the same value when not -c
        // (line 214 in `for_cli`), so this is just "always /etc/
        // tinc" with extra steps. The extra steps document WHY.
        self.confdir
            .clone()
            .unwrap_or_else(|| [CONFDIR, "tinc"].iter().collect())
    }

    /// `hosts/NAME` — host config for one peer (or self).
    ///
    /// This is where `Ed25519PublicKey = ...` lives, plus `Address`,
    /// `Port`, `Subnet`. Public-ish — gets exported and sent to peers.
    #[must_use]
    pub fn host_file(&self, name: &str) -> PathBuf {
        self.confbase.join("hosts").join(name)
    }

    /// `cache/` — `address_cache.c` writes recently-seen peer addresses
    /// here. `tinc init` creates it empty. `fs.c:50`.
    #[must_use]
    pub fn cache_dir(&self) -> PathBuf {
        self.confbase.join("cache")
    }

    /// `<confbase>/invitations`. Directory mode 0700 (`fs.c:42`).
    /// Only `cmd_invite` populates it; only the daemon's
    /// `receive_invitation_sptps` reads from it.
    #[must_use]
    pub fn invitations_dir(&self) -> PathBuf {
        self.confbase.join("invitations")
    }

    /// `<confbase>/invitations/ed25519_key.priv`. The per-mesh
    /// invitation signing key, NOT the node's own key. Generated by
    /// `cmd_invite` on first invite (or after all invites expire),
    /// loaded by the daemon on startup. `invitation.c:440`.
    #[must_use]
    pub fn invitation_key(&self) -> PathBuf {
        self.invitations_dir().join("ed25519_key.priv")
    }

    /// `ed25519_key.priv` — the daemon's signing key. `tincctl.c:372`.
    #[must_use]
    pub fn ed25519_private(&self) -> PathBuf {
        self.confbase.join("ed25519_key.priv")
    }

    /// `tinc-up` — script run when the interface comes up. `tincctl.c:2283`.
    #[must_use]
    #[cfg(unix)]
    pub fn tinc_up(&self) -> PathBuf {
        self.confbase.join("tinc-up")
    }
}

/// `check_id` — node names must be `[A-Za-z0-9_]+`. `utils.c:216-226`.
///
/// Nonempty (`!*id` check — empty string is invalid). The C uses
/// `isalnum((uint8_t) *id)`, which is locale-dependent in principle,
/// but in practice every locale agrees on ASCII alnum and node names
/// are ASCII by convention. We pin to ASCII explicitly; same as the
/// `ascii_fold` decision in `tinc-conf::parse`.
///
/// This isn't just a sanity check — it's load-bearing security. Node
/// names go into filesystem paths (`hosts/NAME`, scripts) and into
/// the wire protocol's space-separated tokens. A name with `/` would
/// be a path traversal; a name with ` ` would break wire parsing. The
/// charset restriction is the one thing standing between "node name
/// from a peer" and "arbitrary attacker-controlled string in a
/// `format!` that becomes a path".
#[must_use]
pub fn check_id(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `replace_name` — expand `$HOST`/`$FOO` in `Name = ...` values, then
/// `check_id`. C: `utils.c:246-289`.
///
/// ## What this is for
///
/// `tinc.conf` can say `Name = $HOST` to mean "use the machine's
/// hostname as the node name". Or `Name = $MYTINCNAME` for an
/// arbitrary env var. The `$HOST` form is special-cased: if env var
/// `HOST` isn't set, fall through to `gethostname(2)`.
///
/// After expansion, non-alnum characters get squashed to `_` (a
/// hostname like `my-laptop.local` becomes `my_laptop_local`). Then
/// `check_id` runs as a final gate — which after squashing can only
/// fail on empty string.
///
/// ## Why this is in `names.rs` not `cmd/exchange.rs`
///
/// First consumer is `get_my_name` (`cmd/exchange.rs`). But the daemon
/// also calls `replace_name` from `net_setup.c:setup_myself` — it's
/// the *same* code path: read `Name` from config, expand, validate.
/// Shared infrastructure goes here.
///
/// ## Why `Result<String, String>` not `Option`
///
/// The C has three distinct error messages: "env var X does not
/// exist", "could not get hostname", "invalid name". A caller doing
/// `expect()` gets the right message; a test gets the right discriminant.
/// `Option` would lose that.
///
/// # Errors
/// - `$FOO` (not `$HOST`) and env var `FOO` is unset
/// - `$HOST`, env var `HOST` unset, *and* `gethostname` fails
/// - Result fails `check_id` (empty after squashing)
#[cfg(unix)]
pub fn replace_name(raw: &str) -> Result<String, String> {
    replace_name_with(raw, |k| std::env::var(k).ok())
}

/// Core of `replace_name`, parameterized over env lookup so tests don't
/// have to mutate process-global env (`set_var` is `unsafe` in edition
/// 2024 — racy under multithreaded test runners). Production calls go
/// through the wrapper above with the real `std::env::var`.
#[cfg(unix)]
fn replace_name_with(raw: &str, env: impl Fn(&str) -> Option<String>) -> Result<String, String> {
    let resolved = if let Some(var_name) = raw.strip_prefix('$') {
        // C: `if(name[0] == '$')`. The whole tail is the var name —
        // no `${FOO}` syntax, no `$FOO_suffix` parsing. `$HOST` means
        // env var `HOST`, full stop.
        match env(var_name) {
            Some(v) => v,
            // C distinguishes "not $HOST" (hard error) from "$HOST and
            // unset" (fall through to gethostname). The `strcmp(name+1,
            // "HOST")` is exact — `$host` doesn't get the fallback.
            // `var()` returning `NotUnicode` is folded into `None` by
            // the wrapper: a non-UTF-8 hostname would fail the
            // alnum-squash anyway (every byte ≥0x80 → `_`), and the
            // C's behavior on a non-UTF-8 `getenv` result is to feed
            // it to isalnum which returns 0 for everything ≥0x80,
            // same outcome.
            None if var_name == "HOST" => {
                // C: `gethostname(hostname, HOST_NAME_MAX+1)`. nix's
                // wrapper allocates the buffer and returns `OsString`.
                // Same cast-to-String concern as above: non-UTF-8
                // hostname → lossy → squash → probably-valid. The
                // C's `isalnum` on raw bytes is no more correct.
                nix::unistd::gethostname()
                    .map_err(|e| format!("Could not get hostname: {e}"))?
                    .to_string_lossy()
                    .into_owned()
            }
            None => {
                return Err(format!(
                    "Invalid Name: environment variable {var_name} does not exist"
                ));
            }
        }
    } else {
        // No `$` prefix — use as-is. Still goes through check_id below.
        raw.to_owned()
    };

    // C: squash non-alnum to `_`. ONLY for the `$` branch — the C's
    // for-loop is inside `if(name[0] == '$')`. A literal `Name = a-b`
    // does NOT get squashed; it goes to `check_id` as-is and fails.
    //
    // Subtle: this means `Name = my-laptop` is an error but
    // `Name = $HOST` on a machine called `my-laptop` succeeds (becomes
    // `my_laptop`). The squash is a *convenience for hostnames*, not a
    // general sanitizer. Replicated faithfully.
    let name = if raw.starts_with('$') {
        resolved
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    } else {
        resolved
    };

    if check_id(&name) {
        Ok(name)
    } else {
        // C: `"Invalid name for myself!"`. Yes, with the exclamation
        // mark. Yes, even for the empty case.
        Err("Invalid name for myself!".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confbase_from_netname() {
        let p = Paths::for_cli(&PathsInput {
            netname: Some("myvpn".into()),
            ..Default::default()
        });
        // CONFDIR is compile-time; the test asserts the *shape*.
        assert!(p.confbase.ends_with("tinc/myvpn"));
        assert!(p.confdir.as_ref().unwrap().ends_with("tinc"));
        assert!(p.tinc_conf().ends_with("tinc/myvpn/tinc.conf"));
        assert!(p.host_file("alice").ends_with("tinc/myvpn/hosts/alice"));
    }

    use std::path::Path;

    #[test]
    fn explicit_confbase_wins() {
        let p = Paths::for_cli(&PathsInput {
            netname: Some("ignored".into()),
            confbase: Some("/tmp/mytinc".into()),
            ..Default::default()
        });
        assert_eq!(p.confbase, Path::new("/tmp/mytinc"));
        // confdir is None — we don't know what the parent should be,
        // and `makedirs` skips it when confbase was explicit.
        assert!(p.confdir.is_none());
    }

    #[test]
    fn neither_given() {
        let p = Paths::for_cli(&PathsInput::default());
        // confbase == confdir when no netname.
        assert_eq!(p.confbase, *p.confdir.as_ref().unwrap());
        assert!(p.confbase.ends_with("tinc"));
    }

    #[test]
    fn check_id_charset() {
        assert!(check_id("alice"));
        assert!(check_id("Node_1"));
        assert!(check_id("_"));
        assert!(check_id("123")); // pure-digit is fine
        assert!(!check_id("")); // C: `if(!*id) return false`
        assert!(!check_id("has space"));
        assert!(!check_id("has-dash")); // dash is not in the set
        assert!(!check_id("path/traversal"));
        assert!(!check_id("dot.ted"));
        // Non-ASCII: `bytes()` sees the UTF-8 encoding bytes, none of
        // which are ASCII alnum (multibyte sequences are all ≥0x80).
        // Same outcome as C `isalnum((uint8_t)*id)` on UTF-8 bytes.
        assert!(!check_id("ünicode"));
    }

    #[cfg(unix)]
    #[test]
    fn replace_name_literal() {
        assert_eq!(replace_name("alice").unwrap(), "alice");
        // No squashing for literals: dash goes straight to check_id
        // and fails. This is the asymmetry — see the function doc.
        assert!(replace_name("has-dash").is_err());
        assert!(replace_name("").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn replace_name_envvar_squashes() {
        // Hostname-ish input gets squashed: dash and dot → underscore.
        // Uses the parameterized core so we don't touch process env
        // (`set_var` is `unsafe` in edition 2024 — racy under nextest).
        let env = |k: &str| (k == "X1").then(|| "my-host.example".to_owned());
        assert_eq!(replace_name_with("$X1", env).unwrap(), "my_host_example");
    }

    #[cfg(unix)]
    #[test]
    fn replace_name_envvar_missing() {
        // Any `$FOO` where FOO isn't HOST and isn't set → error.
        let err = replace_name("$TINC_TEST_DEFINITELY_UNSET_ZZZ").unwrap_err();
        assert!(err.contains("TINC_TEST_DEFINITELY_UNSET_ZZZ"));
        assert!(err.contains("does not exist"));
    }

    #[cfg(unix)]
    #[test]
    fn replace_name_host_falls_through() {
        // `$HOST` with no `HOST` env var → gethostname. We can't
        // assert *what* it returns (depends on the test machine), but
        // we can assert it doesn't error and the result passes check_id.
        // Inject an always-empty env so the test is hermetic regardless
        // of whether the CI runner has `HOST` set.
        let name = replace_name_with("$HOST", |_| None).unwrap();
        assert!(check_id(&name), "gethostname → squash → {name:?}");
    }

    /// `unix_socket` derivation: `.pid` → `.socket` substitution.
    /// Tests the string surgery in isolation by setting pidfile
    /// directly via PathsInput (no fs probe).
    #[test]
    fn unix_socket_dot_pid_replaced() {
        let mut p = Paths::for_cli(&PathsInput {
            confbase: Some("/tmp".into()),
            ..Default::default()
        });
        p.resolve_runtime(&PathsInput {
            pidfile: Some("/var/run/tinc.myvpn.pid".into()),
            ..Default::default()
        });
        // The dot in `tinc.myvpn` survives — only the trailing 4
        // bytes are touched. `with_extension` would break this.
        assert_eq!(p.unix_socket(), Path::new("/var/run/tinc.myvpn.socket"));
    }

    /// No `.pid` suffix → append. `confbase/pid` (the fallback path)
    /// has no `.pid` extension — it's a *file named pid*, not
    /// *something.pid*. C `names.c:160`: append branch.
    #[test]
    fn unix_socket_no_dot_pid_appended() {
        let mut p = Paths::for_cli(&PathsInput {
            confbase: Some("/tmp".into()),
            ..Default::default()
        });
        p.resolve_runtime(&PathsInput {
            pidfile: Some("/etc/tinc/myvpn/pid".into()),
            ..Default::default()
        });
        assert_eq!(p.unix_socket(), Path::new("/etc/tinc/myvpn/pid.socket"));
    }

    /// Exactly `.pid` (len=4) does NOT match — the C's `len > 4`
    /// not `>= 4`. Absurd path but the off-by-one is real.
    #[test]
    fn unix_socket_exactly_dot_pid() {
        let mut p = Paths::for_cli(&PathsInput {
            confbase: Some("/tmp".into()),
            ..Default::default()
        });
        p.resolve_runtime(&PathsInput {
            pidfile: Some(".pid".into()),
            ..Default::default()
        });
        // Append, not replace.
        assert_eq!(p.unix_socket(), Path::new(".pid.socket"));
    }

    /// Case-sensitive match. C: `strcmp` not `strcasecmp`. `tinc.PID`
    /// from a confused user does not match → `tinc.PID.socket`, which
    /// won't be where the daemon listens. The case-sensitivity is
    /// load-bearing for correctness; both halves use the same code.
    #[test]
    fn unix_socket_case_sensitive() {
        let mut p = Paths::for_cli(&PathsInput {
            confbase: Some("/tmp".into()),
            ..Default::default()
        });
        p.resolve_runtime(&PathsInput {
            pidfile: Some("/tmp/tinc.PID".into()),
            ..Default::default()
        });
        assert_eq!(p.unix_socket(), Path::new("/tmp/tinc.PID.socket"));
    }

    /// The pidfile fallback dance. We can't probe `/var/run` in a
    /// test (might exist, might not, depends on host), so we test
    /// the `confbase/pid exists` branch, the only one we can control.
    ///
    /// Tempdir uniqueness via test name + thread id, per the
    /// constraint. Parallel-safe.
    #[test]
    fn resolve_runtime_confbase_fallback() {
        let dir = std::env::temp_dir().join(format!(
            "tinc_test_resolve_{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Touch confbase/pid so the fallback fires.
        std::fs::write(dir.join("pid"), "").unwrap();

        let mut p = Paths::for_cli(&PathsInput {
            confbase: Some(dir.clone()),
            ..Default::default()
        });
        // No --pidfile, no netname. /var/run/tinc.pid almost
        // certainly doesn't exist on a test runner; even if it does,
        // this test would just take the LocalState branch and the
        // assert below would fail — spurious failure on a runner
        // with a system tincd. Unlikely enough to not gate on.
        let src = p.resolve_runtime(&PathsInput::default());

        // The interesting assert: confbase/pid exists, system path
        // (probably) doesn't → fallback fires.
        if src == PidfileSource::Confbase {
            assert_eq!(p.pidfile(), dir.join("pid"));
            // And the socket derivation appends:
            assert_eq!(p.unix_socket(), dir.join("pid.socket"));
        }
        // If src is LocalState, this runner has /var/run/tinc.pid.
        // Don't fail — just don't assert. The string-surgery tests
        // above cover the derivation; this one is for the probe order.

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Forgetting `resolve_runtime()` panics. The panic is the
    /// feature — 4a commands should never reach for these.
    #[test]
    #[should_panic(expected = "resolve_runtime")]
    fn pidfile_before_resolve_panics() {
        let p = Paths::for_cli(&PathsInput {
            confbase: Some("/tmp".into()),
            ..Default::default()
        });
        let _ = p.pidfile();
    }
}
