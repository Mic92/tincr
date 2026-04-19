//! `Name = $HOST` / `Name = $FOO` expansion.
//!
//! Shared by `tincd` (daemon startup) and `tinc-tools` (`export`,
//! `get_my_name`). Previously each had its own copy with *different*
//! semantics — the daemon truncated the hostname at the first `.`,
//! the CLI didn't — so `tinc export` on `my-host.lan` wrote
//! `hosts/my_host_lan` while the daemon booted as `my_host` and read
//! `hosts/my_host` (missing). Peers then rejected the connection
//! because the exchanged host file's name didn't match.
//!
//! The function is parameterized over env lookup and `gethostname` so
//! this crate stays free of `nix`/`libc` and tests don't mutate
//! process-global env (`set_var` is `unsafe` in edition 2024 and racy
//! under parallel test runners). Callers supply the real lookups.
//!
//! Semantics match upstream `net_setup.c`:
//!
//! - Literal `Name = foo` → validated with [`check_id`], returned
//!   unchanged. No squashing: `Name = a-b` is an error.
//! - `Name = $VAR` → `env(VAR)`; if unset and `VAR == "HOST"`, fall
//!   through to `gethostname()`. The result is truncated at the first
//!   `.` (strip the domain part) and every non-`[A-Za-z0-9_]` byte is
//!   squashed to `_`. So hostname `my-host.lan` → `my_host`.

/// Node-name charset check: non-empty `[A-Za-z0-9_]+`.
///
/// Same one-liner as `tinc_proto::check_id`; duplicated here so
/// `tinc-conf` doesn't grow a dep on `tinc-proto` for one predicate.
#[must_use]
pub fn check_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Expand `Name = ...` per the module doc.
///
/// `env(VAR)` returns the env var value or `None`. `gethostname()` is
/// called only for `$HOST` when `env("HOST")` is `None`.
///
/// # Errors
/// - Literal name fails [`check_id`] (including empty).
/// - `$VAR` (not `$HOST`) and `env(VAR)` is `None`.
/// - `$HOST`, `env("HOST")` is `None`, and `gethostname()` fails.
/// - Expanded result is empty after truncate+squash.
pub fn expand_name(
    raw: &str,
    env: impl Fn(&str) -> Option<String>,
    gethostname: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    let Some(var) = raw.strip_prefix('$') else {
        if !check_id(raw) {
            return Err(format!("Invalid Name: {raw}"));
        }
        return Ok(raw.to_owned());
    };

    let resolved = match env(var) {
        Some(v) => v,
        None if var == "HOST" => gethostname()?,
        None => {
            return Err(format!(
                "Invalid Name: environment variable {var} does not exist"
            ));
        }
    };

    // Strip domain part: `my-host.lan` → `my-host`. Upstream does
    // this for the gethostname fallback; we do it for env-supplied
    // values too so `HOST=foo.bar` and hostname `foo.bar` agree.
    let short = resolved.split('.').next().unwrap_or(&resolved);

    // Squash non-alnum to `_`; `_` itself is preserved deliberately
    // (not just by the accident of `is_ascii_alphanumeric` → false).
    let name: String = short
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if check_id(&name) {
        Ok(name)
    } else {
        // Only reachable on empty result (e.g. hostname ".lan").
        Err("Invalid name for myself!".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }
    fn no_host() -> Result<String, String> {
        Err("unreachable".into())
    }

    #[test]
    fn literal_not_squashed() {
        assert_eq!(expand_name("alice", no_env, no_host).unwrap(), "alice");
        // The squash is a convenience for hostnames, not a general
        // sanitizer: a literal dash goes straight to check_id and
        // fails. Asymmetry is intentional (matches upstream).
        assert!(expand_name("has-dash", no_env, no_host).is_err());
        assert!(expand_name("", no_env, no_host).is_err());
    }

    /// The bug this module exists to fix: both the CLI and the daemon
    /// must agree on what `$HOST` expands to. Hostname `my-host.lan`
    /// → `my_host` (truncate at dot, squash dash), NOT `my_host_lan`.
    #[test]
    fn host_truncates_at_dot_and_squashes() {
        let n = expand_name("$HOST", no_env, || Ok("my-host.lan".into())).unwrap();
        assert_eq!(n, "my_host");
    }

    #[test]
    fn envvar_same_semantics_as_host() {
        // Env-supplied values get the same truncate+squash so
        // `HOST=foo.bar` in env and hostname `foo.bar` agree.
        let env = |k: &str| (k == "X").then(|| "a-b.c".to_owned());
        assert_eq!(expand_name("$X", env, no_host).unwrap(), "a_b");
    }

    #[test]
    fn underscore_preserved() {
        let env = |k: &str| (k == "X").then(|| "dev_box".to_owned());
        assert_eq!(expand_name("$X", env, no_host).unwrap(), "dev_box");
    }

    #[test]
    fn host_env_beats_gethostname() {
        let env = |k: &str| (k == "HOST").then(|| "fromenv".to_owned());
        let n = expand_name("$HOST", env, || panic!("should not call")).unwrap();
        assert_eq!(n, "fromenv");
    }

    #[test]
    fn empty_after_truncate_errors() {
        let err = expand_name("$HOST", no_env, || Ok(".lan".into())).unwrap_err();
        assert!(err.contains("Invalid name"));
    }
}
