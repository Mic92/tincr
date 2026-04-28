//! Diff-core for `reload_configuration`: pure functions for the
//! subnets / `ConnectTo` / conn-mtime diffs.
//!
//! C uses `subnet->expires` as a mark bit and sweeps a splay tree;
//! we have `HashSet` and use two `difference` calls.
//!
//! `setup()` is one-shot (creates listeners, opens TUN). The
//! reloadable subset is settings + subnets + `ConnectTo` +
//! conn-revoke. `last_config_check` initialises to daemon-start
//! time; `setup()` updates it.
//!
//! `strictsubnets` reload diff is not yet implemented — see
//! `TODO(strictsubnets-reload)` in `daemon/tx_control.rs`.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashSet};
use std::hash::BuildHasher;
use std::time::SystemTime;

use tinc_proto::Subnet;

/// Result of diffing old subnets against new config.
///
/// ## Subnet identity includes weight
///
/// `Subnet`'s derived `Eq`/`Hash` includes the `weight` field. So
/// `10.0.0.0/24 weight 5` ≠ `10.0.0.0/24 weight 10`. Changing a
/// weight in the config is remove-old + add-new. `subnet_compare_*`
/// includes weight in the key, so `lookup_subnet` won't find the
/// old entry when weight changed → falls through to the add path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SubnetDiff {
    /// New in config, not in current set. → `subnet_add` +
    /// `send_add_subnet(everyone)` + `subnet_update(true)`.
    pub added: Vec<Subnet>,
    /// In current set, not in new config. → `send_del_subnet` +
    /// `subnet_update(false)` + `subnet_del`.
    pub removed: Vec<Subnet>,
    // No "kept" field — caller doesn't need to act on those.
}

/// The subnet mark-sweep.
///
/// `current`: subnets owned by `myself` right now.
/// `from_config`: subnets parsed from the re-read `Subnet =` lines
///   in `hosts/NAME`.
///
/// Ordering of `added`/`removed`: `HashSet::difference` iteration
/// order — non-deterministic across runs. Doesn't matter (each
/// subnet is independent; the C is splay-tree iter order, also just
/// "some deterministic order").
#[must_use]
pub(crate) fn diff_subnets<S: BuildHasher>(
    current: &HashSet<Subnet, S>,
    from_config: &HashSet<Subnet, S>,
) -> SubnetDiff {
    SubnetDiff {
        added: from_config.difference(current).copied().collect(),
        removed: current.difference(from_config).copied().collect(),
    }
}

/// `try_outgoing_connections` mark-sweep + re-kick.
///
/// `current`: `ConnectTo` names with active outgoings.
/// `from_config`: `ConnectTo =` lines in re-read tinc.conf.
///
/// Returns `(to_add, to_remove)`. `to_add` → daemon calls
/// `setup_outgoing_connection`. `to_remove` → daemon terminates the
/// outgoing (and its conn if connected).
///
/// The C marks every outgoing `outgoing->aip = NULL` (the "address
/// iterator pointer" — `NULL` means "stale"), then the config-read
/// clears it for survivors. Same pattern.
///
/// Ordering: `BTreeSet::difference` — deterministic, sorted. Node
/// names are `[A-Za-z0-9_]+` so byte-lex == ASCII-lex.
#[must_use]
pub(crate) fn diff_connect_to(
    current: &BTreeSet<String>,
    from_config: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let to_add = from_config.difference(current).cloned().collect();
    let to_remove = current.difference(from_config).cloned().collect();
    (to_add, to_remove)
}

/// Which conns need terminating because their hosts/ file changed
/// since last reload.
///
/// `conns`: active connection names (excluding control conns —
///   caller filters).
/// `host_mtimes`: `(name, mtime)` for each conn whose `hosts/{name}`
///   exists. The daemon does the `stat`; this function decides.
///   Missing hosts/ file → conn IS in `conns` but NOT in
///   `host_mtimes`; that's a TERMINATE (the operator deleted the
///   file → revoke).
/// `last_check`: `last_config_check` from previous reload (or
///   daemon start).
///
/// `if(stat(fname, &s) || s.st_mtime > last_config_check)`: the `||`
/// means stat-failed (ENOENT, deleted) OR newer. Both terminate.
///
/// ## `>` not `>=` — one-second granularity
///
/// `s.st_mtime > last_config_check`: strict greater-than. `st_mtime`
/// is seconds. So if you
/// reload twice in the same wall-clock second, a file written
/// *between* the reloads has `mtime == last_check` and does NOT
/// trigger. The C has this issue too. We replicate it: changing the
/// comparison to `>=` would terminate every conn on every reload
/// (every hosts/ file's mtime is `>=` daemon start time on a fresh
/// install). Don't fix.
#[must_use]
pub(crate) fn conns_to_terminate(
    conns: &[String],
    host_mtimes: &[(String, SystemTime)],
    last_check: SystemTime,
) -> Vec<String> {
    conns
        .iter()
        .filter(|name| {
            match host_mtimes
                .iter()
                .find(|(n, _)| n == name.as_str())
                .map(|(_, mtime)| *mtime)
            {
                // `stat()` failed (ENOENT) — file deleted, revoke.
                None => true,
                // Strict `>` — see `conns_to_terminate` doc.
                Some(mtime) => mtime > last_check,
            }
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8, weight: i32) -> Subnet {
        Subnet::V4 {
            addr: Ipv4Addr::new(a, b, c, d),
            prefix,
            weight,
        }
    }

    fn set<T: std::hash::Hash + Eq>(xs: impl IntoIterator<Item = T>) -> HashSet<T> {
        xs.into_iter().collect()
    }

    // ─── diff_subnets ───────────────────────────────────────────────

    #[test]
    fn subnets_no_change() {
        let s = set([v4(10, 0, 0, 0, 24, 10), v4(192, 168, 1, 0, 24, 10)]);
        let diff = diff_subnets(&s, &s);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn subnets_one_added() {
        let current = set([v4(10, 0, 0, 0, 24, 10)]);
        let new = set([v4(10, 0, 0, 0, 24, 10), v4(10, 0, 1, 0, 24, 10)]);
        let diff = diff_subnets(&current, &new);
        assert_eq!(diff.added, vec![v4(10, 0, 1, 0, 24, 10)]);
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn subnets_one_removed() {
        let current = set([v4(10, 0, 0, 0, 24, 10), v4(10, 0, 1, 0, 24, 10)]);
        let new = set([v4(10, 0, 0, 0, 24, 10)]);
        let diff = diff_subnets(&current, &new);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec![v4(10, 0, 1, 0, 24, 10)]);
    }

    #[test]
    fn subnets_full_replace() {
        let a = v4(10, 0, 0, 0, 24, 10);
        let b = v4(10, 0, 1, 0, 24, 10);
        let c = v4(172, 16, 0, 0, 16, 10);
        let d = v4(192, 168, 0, 0, 16, 10);
        let diff = diff_subnets(&set([a, b]), &set([c, d]));
        // HashSet iter order is non-deterministic; compare as sets.
        assert_eq!(set(diff.added), set([c, d]));
        assert_eq!(set(diff.removed), set([a, b]));
    }

    /// Weight is part of `Subnet`'s `Eq`. Changing weight in config
    /// is remove-old + add-new. C behaves identically:
    /// `subnet_compare_ipv4` keys on weight, so `lookup_subnet`
    /// misses → both branches fire.
    #[test]
    fn subnets_same_addr_different_weight() {
        let old = v4(10, 0, 0, 0, 24, 5);
        let new = v4(10, 0, 0, 0, 24, 10);
        let diff = diff_subnets(&set([old]), &set([new]));
        assert_eq!(diff.added, vec![new]);
        assert_eq!(diff.removed, vec![old]);
    }

    // ─── diff_connect_to ────────────────────────────────────────────

    #[test]
    fn connect_to_diff() {
        let current: BTreeSet<String> = ["bob".to_string(), "carol".to_string()].into();
        let new: BTreeSet<String> = ["bob".to_string(), "dave".to_string()].into();
        let (add, remove) = diff_connect_to(&current, &new);
        assert_eq!(add, vec!["dave".to_string()]);
        assert_eq!(remove, vec!["carol".to_string()]);
    }

    #[test]
    fn connect_to_no_change() {
        let s: BTreeSet<String> = ["bob".to_string(), "carol".to_string()].into();
        let (add, remove) = diff_connect_to(&s, &s);
        assert!(add.is_empty());
        assert!(remove.is_empty());
    }

    // ─── conns_to_terminate ─────────────────────────────────────────

    #[test]
    fn conns_to_terminate_mtime_newer() {
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let mtime = last + Duration::from_secs(1);
        let out = conns_to_terminate(&["bob".to_string()], &[("bob".to_string(), mtime)], last);
        assert_eq!(out, vec!["bob".to_string()]);
    }

    #[test]
    fn conns_to_terminate_mtime_older() {
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let mtime = last - Duration::from_secs(1);
        let out = conns_to_terminate(&["bob".to_string()], &[("bob".to_string(), mtime)], last);
        assert!(out.is_empty());
    }

    /// `stat()` fails → terminate. Operator deleted `hosts/bob` →
    /// revoke bob.
    #[test]
    fn conns_to_terminate_file_deleted() {
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let out = conns_to_terminate(
            &["bob".to_string()],
            &[], // no entry for bob → stat failed
            last,
        );
        assert_eq!(out, vec!["bob".to_string()]);
    }

    /// `>`, not `>=`. mtime == `last_check` → KEEP.
    /// One-second granularity caveat: see module doc.
    #[test]
    fn conns_to_terminate_mtime_exactly_equal() {
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let out = conns_to_terminate(&["bob".to_string()], &[("bob".to_string(), last)], last);
        assert!(out.is_empty());
    }

    #[test]
    fn conns_to_terminate_mixed() {
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let older = last - Duration::from_secs(10);
        let newer = last + Duration::from_secs(10);
        let out = conns_to_terminate(
            &[
                "alice".to_string(), // older → keep
                "bob".to_string(),   // newer → terminate
                "carol".to_string(), // missing → terminate
                "dave".to_string(),  // equal → keep
            ],
            &[
                ("alice".to_string(), older),
                ("bob".to_string(), newer),
                ("dave".to_string(), last),
            ],
            last,
        );
        assert_eq!(out, vec!["bob".to_string(), "carol".to_string()]);
    }
}
