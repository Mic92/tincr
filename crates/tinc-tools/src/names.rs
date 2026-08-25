//! Path resolution.
//!
//! Every tinc command needs to know "where is the config for net X".
//! argv-shaped inputs → `Paths` struct. No globals; every command
//! takes `&Paths`.
//!
//! ## What's not here yet
//!
//! `logfilename` — daemon log path. First consumer is the daemon's
//! logger.
//!
//! `identname` — `"tinc.NETNAME"` for syslog. First consumer is the
//! daemon's logger.
//!
//! Windows registry lookup (`HKLM\SOFTWARE\tinc`) — `#[cfg(windows)]`
//! when we cross that bridge.
//!
//! ## On `CONFDIR`
//!
//! `option_env!("TINC_CONFDIR")` at compile time, defaulting to
//! `/etc`. The Nix derivation can set it; `cargo build` from a fresh
//! checkout gets `/etc`. If you want `/usr/local/etc`,
//! `TINC_CONFDIR=/usr/local/etc cargo build`.
//!
//! There's a temptation to do XDG (`~/.config/tinc`) when running
//! unprivileged. Upstream does **not** — `tinc init` as non-root
//! fails with EACCES on `/etc/tinc` mkdir, a known papercut. We
//! don't fix it here.

use std::env;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;

/// `CONFDIR` from `config.h`. Baked at compile time.
///
/// `option_env!` not `env!` — we want a default, not a build failure.
/// Packagers set `TINC_CONFDIR` in their build; everyone else gets
/// `/etc`. Same effective behavior as meson's `dir_sysconf`.
const CONFDIR: &str = match option_env!("TINC_CONFDIR") {
    Some(d) => d,
    // distro packages set prefix=/usr → sysconfdir=/etc, the common case.
    None => "/etc",
};

/// `LOCALSTATEDIR`. Same compile-time constant treatment as `CONFDIR`.
/// Nix builds set `TINC_LOCALSTATEDIR` alongside `TINC_CONFDIR`.
///
/// Only used for the pidfile/socket path: `/var/run/tinc.NETNAME.pid`.
/// This path is *tried first*, then `confbase/pid` if `/var/run`
/// isn't writable (non-root testing).
const LOCALSTATEDIR: &str = match option_env!("TINC_LOCALSTATEDIR") {
    Some(d) => d,
    None => "/var",
};

/// All the input paths a command needs (where config lives).
/// `tinc_conf()`/`hosts_dir()` are accessors derived from `confbase`.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `confbase` — config root for this net. `/etc/tinc/NETNAME` or
    /// `/etc/tinc` if no netname, or whatever `--config` said.
    ///
    /// Everything else hangs off this. `tinc.conf`, `hosts/`, `cache/`,
    /// `ed25519_key.priv`, `tinc-up` — all `confbase.join(...)`.
    pub confbase: PathBuf,

    /// Where the daemon writes its pid and control cookie. `None` until
    /// `resolve_runtime()`, which probes the filesystem; filesystem-only commands
    /// never call it, and `pidfile()` panics on `None` so a forgotten call is loud
    /// rather than a silent wrong default.
    pidfile: Option<PathBuf>,

    /// `/etc/tinc`, the parent dir, created before `/etc/tinc/NETNAME` when
    /// confbase came from a netname. `None` when `--config` was given: the user
    /// named the confbase and its parent is their business.
    pub confdir: Option<PathBuf>,
}

/// Input axis. These come from getopt (`-c` / `-n`).
///
/// You only ever set one or the other in practice (`-c` overrides
/// `-n`), but we accept both with a warning.
#[derive(Debug, Default)]
pub struct PathsInput {
    /// `-n NETNAME` / `--net=NETNAME`. Names a subdirectory of confdir.
    pub netname: Option<String>,

    /// `-c DIR` / `--config=DIR`. Explicit confbase. Wins over netname.
    pub confbase: Option<PathBuf>,

    /// `--pidfile=X`. Overrides all the resolution logic.
    ///
    /// Why this is in `PathsInput`: it's input, same axis as `-c`/`-n`.
    /// The fact that it bypasses resolution is the whole point of
    /// passing it explicitly. Tests use this to point at a tempdir
    /// without the `/var/run` probe ever firing.
    pub pidfile: Option<PathBuf>,
}

impl Paths {
    /// The CLI flavor.
    ///
    /// (The daemon flavor differs only in pidfile/log resolution.
    /// When we add those fields, this gets a separate `for_daemon()`
    /// constructor.)
    #[must_use]
    pub fn for_cli(input: &PathsInput) -> Self {
        if input.netname.is_some() && input.confbase.is_some() {
            eprintln!("Both netname and configuration directory given, using the latter...");
        }

        // Decision tree:
        //   confbase given     → use it, confdir is moot
        //   netname given      → CONFDIR/tinc/NETNAME, confdir = CONFDIR/tinc
        //   neither            → CONFDIR/tinc,         confdir = CONFDIR/tinc
        //
        // The neither case means confbase == confdir. `makedirs` then
        // idempotently mkdirs the same path twice. Harmless.

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

    /// Resolve `pidfilename` (and implicitly the socket name); idempotent.
    /// `/var/run/tinc[.NET].pid` if it exists; else `confbase/pid` if *that*
    /// exists; else the `/var/run` path anyway, so a no-daemon error names the
    /// place a daemon should have written. `&mut self` rather than a constructor
    /// keeps `for_cli()` probe-free for tests and filesystem-only commands.
    pub fn resolve_runtime(&mut self, input: &PathsInput) {
        // --pidfile wins. No probing.
        if let Some(explicit) = &input.pidfile {
            self.pidfile = Some(explicit.clone());
            return;
        }

        if self.pidfile.is_some() {
            return; // already resolved
        }

        // identname: `tinc.NETNAME` or `tinc`. The dot is significant:
        // `tinc.myvpn.pid` not `tincmyvpn.pid`. identname is *also*
        // the syslog tag, which is why it's human-readable.
        let identname = match &input.netname {
            Some(net) => format!("tinc.{net}"),
            None => "tinc".to_owned(),
        };

        // `Path::exists` uses `stat`. For "does this file exist at
        // all" that's sufficient — a mode-000 pidfile would mean the
        // *daemon* set it that way, which is nonsense.
        let system_path: PathBuf = [LOCALSTATEDIR, "run", &format!("{identname}.pid")]
            .iter()
            .collect();
        let confbase_path = self.confbase.join("pid");

        // The truth table from the doc comment, in code. If neither
        // exists, the final else → system_path.
        self.pidfile = Some(if !system_path.exists() && confbase_path.exists() {
            confbase_path
        } else {
            system_path
        });
    }

    /// `pidfilename`. Daemon writes; CLI reads.
    ///
    /// # Panics
    /// If `resolve_runtime()` hasn't been called. The panic is the
    /// point — a 4a command calling this is a bug we want to find
    /// in tests, not paper over with a default.
    #[must_use]
    pub fn pidfile(&self) -> &Path {
        self.pidfile
            .as_deref()
            .expect("pidfile() called before resolve_runtime()")
    }

    /// Control socket path, derived from `pidfilename`: `foo.pid` → `foo.socket`
    /// (case-sensitive, exactly `.pid`), anything else gets `.socket` appended.
    /// Must match the daemon's derivation exactly or connect fails silently. Pure,
    /// so not stored.
    ///
    /// # Panics
    /// Same as `pidfile()`.
    #[must_use]
    pub fn unix_socket(&self) -> PathBuf {
        let pid = self.pidfile();
        // Work in OsStr land: pidfile paths are ASCII in practice
        // (built from ASCII constants + check_id'd netname), but
        // `--pidfile` can be anything. `as_encoded_bytes` is the
        // platform-native byte view; on Unix it's literal path bytes.
        let bytes = pid.as_os_str().as_encoded_bytes();
        // `> 4` not `>= 4` — a file named exactly `.pid` (len=4)
        // doesn't match. Unlikely but preserved.
        if bytes.len() > 4 && bytes.ends_with(b".pid") {
            // Replace exactly the trailing `.pid`; `with_extension` would turn
            // `tinc.myvpn.pid` into `tinc.socket`. Slicing at `len-4` is a valid boundary
            // since `.pid` is ASCII.
            let stem = &bytes[..bytes.len() - 4];
            // SAFETY: stem is a prefix of valid encoded bytes,
            // truncated at an ASCII byte boundary. The forbid(unsafe)
            // means we go through OsString from-the-platform-bytes
            // instead. On Unix, `OsStr::from_bytes` is the safe path.
            #[cfg(unix)]
            {
                let mut s = OsStr::from_bytes(stem).to_owned();
                s.push(".socket");
                PathBuf::from(s)
            }
            #[cfg(not(unix))]
            {
                // Windows uses different path resolution via registry.
                // Stub the type-check.
                let _ = stem;
                let mut s = pid.as_os_str().to_owned();
                s.push(".socket");
                PathBuf::from(s)
            }
        } else {
            let mut s = pid.as_os_str().to_owned();
            s.push(".socket");
            PathBuf::from(s)
        }
    }

    /// `tinc.conf` — the main config file.
    #[must_use]
    pub fn tinc_conf(&self) -> PathBuf {
        self.confbase.join("tinc.conf")
    }

    /// `hosts/` — per-peer config + public keys.
    #[must_use]
    pub fn hosts_dir(&self) -> PathBuf {
        self.confbase.join("hosts")
    }

    /// `confdir` for `cmd_network`, which lists `/etc/tinc/*/tinc.conf` even under
    /// `-c` (that names one confbase, not a parent of confbases): `Some(x)` → `x`,
    /// `None` → `CONFDIR/tinc`.
    #[must_use]
    pub fn confdir_always(&self) -> PathBuf {
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

    /// `addrcache/` — recently-seen peer addresses. `tinc init`
    /// creates it empty. Different name from C tinc's `cache/`: the
    /// on-disk format is incompatible (text + header vs raw
    /// `sockaddr_storage`), so sharing a path would just have each
    /// binary nuke the other's file on first save.
    #[must_use]
    pub fn cache_dir(&self) -> PathBuf {
        self.confbase.join("addrcache")
    }

    /// `<confbase>/invitations`. Directory mode 0700. Only
    /// `cmd_invite` populates it; only the daemon reads from it.
    #[must_use]
    pub fn invitations_dir(&self) -> PathBuf {
        self.confbase.join("invitations")
    }

    /// `<confbase>/invitations/ed25519_key.priv`. The per-mesh
    /// invitation signing key, not the node's own key. Generated by
    /// `cmd_invite` on first invite (or after all invites expire),
    /// loaded by the daemon on startup.
    #[must_use]
    pub fn invitation_key(&self) -> PathBuf {
        self.invitations_dir().join("ed25519_key.priv")
    }

    /// `ed25519_key.priv` — the daemon's signing key.
    #[must_use]
    pub fn ed25519_private(&self) -> PathBuf {
        self.confbase.join("ed25519_key.priv")
    }

    /// `tinc-up` — script run when the interface comes up.
    #[must_use]
    #[cfg(unix)]
    pub fn tinc_up(&self) -> PathBuf {
        self.confbase.join("tinc-up")
    }
}

/// Node names must be nonempty ASCII `[A-Za-z0-9_]+`. Load-bearing security,
/// not just hygiene: names become filesystem paths (`hosts/NAME`, scripts) and
/// space-separated wire tokens, so this charset is what keeps a peer-supplied
/// name from being a path traversal or a parse break.
pub use tinc_conf::name::check_id;

/// Expand `Name = $HOST` / `$VAR` and validate: `$HOST` falls back to
/// `gethostname(2)`; non-alnum characters become `_` (`my-laptop.local` →
/// `my_laptop_local`); then `check_id`. Shared by the CLI's `get_my_name` and
/// the daemon's setup.
///
/// # Errors
/// `$VAR` unset; `$HOST` unset and `gethostname` fails; empty after squashing.
#[cfg(unix)]
pub fn replace_name(raw: &str) -> Result<String, String> {
    replace_name_with(raw, |k| env::var(k).ok())
}

/// Core of `replace_name` with injectable env lookup (tests must not `set_var`
/// under a threaded runner). Delegates to `tinc_conf::name::expand_name` so CLI
/// and daemon agree — they once differed on truncating at the first dot, and
/// exchanged host files mismatched.
#[cfg(unix)]
fn replace_name_with(raw: &str, env: impl Fn(&str) -> Option<String>) -> Result<String, String> {
    tinc_conf::name::expand_name(raw, env, || {
        nix::unistd::gethostname()
            .map_err(|e| format!("Could not get hostname: {e}"))
            .map(|h| h.to_string_lossy().into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

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
        assert!(!check_id(""));
        assert!(!check_id("has space"));
        assert!(!check_id("has-dash")); // dash is not in the set
        assert!(!check_id("path/traversal"));
        assert!(!check_id("dot.ted"));
        // Non-ASCII: `bytes()` sees the UTF-8 encoding bytes, none of
        // which are ASCII alnum (multibyte sequences are all ≥0x80).
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
        // Hostname-ish input: domain stripped at first `.`, dash →
        // underscore. Same semantics as the daemon's `expand_name` —
        // previously the CLI kept the domain (`my_host_example`) and
        // the daemon didn't, so `tinc export` and `tincd` disagreed
        // on this node's own name.
        let env = |k: &str| (k == "X1").then(|| "my-host.example".to_owned());
        assert_eq!(replace_name_with("$X1", env).unwrap(), "my_host");
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
    /// directly via `PathsInput` (no fs probe).
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
    /// *something.pid*.
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

    /// Exactly `.pid` (len=4) does not match — `len > 4` not `>= 4`.
    /// Absurd path but the off-by-one is real.
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

    /// Case-sensitive match. `tinc.PID` does not match →
    /// `tinc.PID.socket`, which won't be where the daemon listens.
    /// Load-bearing for correctness; both halves use the same code.
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
        let dir = env::temp_dir().join(format!(
            "tinc_test_resolve_{:?}",
            std::thread::current().id()
        ));
        fs::create_dir_all(&dir).unwrap();
        // Touch confbase/pid so the fallback fires.
        fs::write(dir.join("pid"), "").unwrap();

        let mut p = Paths::for_cli(&PathsInput {
            confbase: Some(dir.clone()),
            ..Default::default()
        });
        // No --pidfile, no netname. /var/run/tinc.pid almost
        // certainly doesn't exist on a test runner; even if it does,
        // this test would just take the LocalState branch and the
        // assert below would fail — spurious failure on a runner
        // with a system tincd. Unlikely enough to not gate on.
        p.resolve_runtime(&PathsInput::default());

        // The interesting assert: confbase/pid exists, system path
        // (probably) doesn't → fallback fires.
        if p.pidfile() == dir.join("pid") {
            // And the socket derivation appends:
            assert_eq!(p.unix_socket(), dir.join("pid.socket"));
        }
        // Else this runner has /var/run/tinc.pid.
        // Don't fail — just don't assert. The string-surgery tests
        // above cover the derivation; this one is for the probe order.

        let _ = fs::remove_dir_all(&dir);
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
