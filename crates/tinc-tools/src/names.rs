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
    let resolved = if let Some(var_name) = raw.strip_prefix('$') {
        // C: `if(name[0] == '$')`. The whole tail is the var name —
        // no `${FOO}` syntax, no `$FOO_suffix` parsing. `$HOST` means
        // env var `HOST`, full stop.
        match std::env::var(var_name) {
            Ok(v) => v,
            // C distinguishes "not $HOST" (hard error) from "$HOST and
            // unset" (fall through to gethostname). The `strcmp(name+1,
            // "HOST")` is exact — `$host` doesn't get the fallback.
            // `var()` returning `NotUnicode` we treat as not-found:
            // a non-UTF-8 hostname would fail the alnum-squash anyway
            // (every byte ≥0x80 → `_`, then likely empty or all-`_`
            // after the leading bytes), and the C's behavior on a
            // non-UTF-8 `getenv` result is to feed it to isalnum which
            // returns 0 for everything ≥0x80, same outcome.
            Err(_) if var_name == "HOST" => {
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
            Err(_) => {
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
            confbase: None,
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
        // `set_var` is process-global and tests run multithreaded.
        // The race would be two threads touching the *same* var name;
        // we use a sufficiently weird name that no other test touches.
        // In edition 2024 `set_var` becomes `unsafe` for exactly this
        // reason — when we bump editions, this test moves to the
        // integration suite (separate binary, own unsafe policy) or
        // `replace_name` grows an env-lookup-closure parameter. Until
        // then, edition 2021's safe `set_var` is fine.
        std::env::set_var("TINC_TEST_REPLACE_NAME_X1", "my-host.example");
        // Hostname-ish input gets squashed: dash and dot → underscore.
        assert_eq!(
            replace_name("$TINC_TEST_REPLACE_NAME_X1").unwrap(),
            "my_host_example"
        );
        std::env::remove_var("TINC_TEST_REPLACE_NAME_X1");
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
        //
        // First, make sure HOST is actually unset. CI runners sometimes
        // set it. (We don't restore it — tests shouldn't depend on
        // ambient HOST.)
        std::env::remove_var("HOST");
        let name = replace_name("$HOST").unwrap();
        assert!(check_id(&name), "gethostname → squash → {name:?}");
    }
}
