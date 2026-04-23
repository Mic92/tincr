//! Per-peer dial-address book.
//!
//! When we want a meta connection to `bob`, [`AddressCache::next_addr`]
//! hands out one candidate `SocketAddr` per call until it runs dry.
//! Candidates come from three places, walked in this order:
//!
//! 1. **recent** — addresses that previously got us all the way to a
//!    completed handshake. Most-recently-working first. This is the
//!    only tier persisted to disk.
//! 2. **known** — addresses learnt at runtime from sources other than
//!    config: edge gossip ("alice last saw bob at …"), DHT records,
//!    off-thread DNS results. The daemon rebuilds this set wholesale
//!    on every retry, so stale gossip doesn't linger.
//! 3. **config** — literal-IP `Address =` lines from `hosts/bob`.
//!    Hostnames in `Address =` are *not* resolved here; they're
//!    surfaced via [`AddressCache::unresolved_hosts`] for the
//!    background resolver and fed back into tier 2 as plain
//!    `SocketAddr`s. `next_addr` therefore never blocks.
//!
//! A "round" is one walk from the top until `next_addr` returns
//! `None`. [`AddressCache::reset`] starts a fresh round (the retry
//! backoff calls it). [`AddressCache::add_recent`] is the learning
//! step: call it with the address that just worked.
//!
//! ## On-disk format
//!
//! `<state-dir>/addrcache/<peer>` — a magic header line followed by
//! up to eight `SocketAddr`s in `Display` form, one per line. Text so
//! it's portable, `cat`-able, and parsed by `str::parse`. The header
//! makes the file self-describing and gives us a version slot. A
//! missing/unrecognised header or an unparseable line yields an empty
//! cache; it's a warm-start hint, never load-bearing.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Only this many `recent` entries are written to disk. The in-memory
/// list is uncapped (config might list more; we try them all, persist
/// the eight most recent successes).
const MAX_PERSISTED: usize = 8;

/// Upper bound on the in-memory `known`/`config` tiers. They're
/// dedup'd with linear scans, so a small fixed cap keeps `next_addr`
/// O(1) regardless of how chatty gossip or DNS are.
const MAX_EPHEMERAL: usize = 64;

/// First line of every cache file. See module docs.
const HEADER: &str = "tinc-addrcache 1";

/// One peer's address book. See module docs for the tier model.
pub(crate) struct AddressCache {
    /// Tier 1. MRU; only this tier persists.
    recent: Vec<SocketAddr>,
    /// Tier 2. Replaced wholesale per retry by
    /// [`Self::add_known_addresses`]; appended to mid-round by
    /// [`Self::extend_resolved`].
    known: Vec<SocketAddr>,
    /// Tier 3. Literal-IP `Address =` lines, parsed at construction.
    config: Vec<SocketAddr>,
    /// Tier 4. Late-arriving resolver results for this round only.
    /// Separate from `known` so appends don't shift the cursor's view
    /// of tiers 2/3 mid-walk. Cleared whenever the cursor resets.
    resolved: Vec<SocketAddr>,
    /// `Address =` lines that weren't literal IPs. Handed to the
    /// background resolver each round.
    hostnames: Vec<(String, u16)>,
    /// Index into `recent ‖ known ‖ config`. Zeroed by `reset` and
    /// `add_known_addresses`.
    cursor: usize,
    /// `None` ⇒ in-memory only (tests, ad-hoc).
    path: Option<PathBuf>,
}

/// Where the on-disk cache lives. `$STATE_DIRECTORY` wins when set:
/// on NixOS the confbase is a read-only store path and tincd runs
/// unprivileged with a systemd `StateDirectory=`. No writability
/// probe — the env var being set *is* the operator's signal that
/// confbase is managed; bare `tincd -n foo` / chroot / BSD have no
/// `$STATE_DIRECTORY` and stay under confbase.
fn resolve_cache_dir(confbase: &Path, state_dir: Option<&Path>) -> PathBuf {
    state_dir.unwrap_or(confbase).join("addrcache")
}

/// Split `Address =` config lines into (literal IPs, hostnames).
/// Literal IPs need no resolver; everything else does.
fn split_config(lines: Vec<(String, u16)>) -> (Vec<SocketAddr>, Vec<(String, u16)>) {
    let mut literals = Vec::new();
    let mut hostnames = Vec::new();
    for (host, port) in lines {
        if let Ok(ip) = host.parse::<IpAddr>() {
            let a = SocketAddr::new(ip, port);
            if !literals.contains(&a) {
                literals.push(a);
            }
        } else {
            let hp = (host, port);
            if !hostnames.contains(&hp) {
                hostnames.push(hp);
            }
        }
    }
    (literals, hostnames)
}

impl AddressCache {
    /// Load `<state-dir>/addrcache/<peer>` (if present) and seed tier
    /// 3 from `config_addrs`. Never fails: unreadable / malformed
    /// cache files degrade to empty.
    #[must_use]
    pub(crate) fn open(confbase: &Path, peer: &str, config_addrs: Vec<(String, u16)>) -> Self {
        let state_dir = std::env::var_os("STATE_DIRECTORY").map(PathBuf::from);
        let path = resolve_cache_dir(confbase, state_dir.as_deref()).join(peer);
        let (config, hostnames) = split_config(config_addrs);
        Self {
            recent: load(&path),
            known: Vec::new(),
            config,
            resolved: Vec::new(),
            hostnames,
            cursor: 0,
            path: Some(path),
        }
    }

    /// In-memory cache seeded with a fixed `recent` list. Test fixture.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn new(recent: Vec<SocketAddr>) -> Self {
        Self {
            recent,
            known: Vec::new(),
            config: Vec::new(),
            resolved: Vec::new(),
            hostnames: Vec::new(),
            cursor: 0,
            path: None,
        }
    }

    /// Replace tier 2 with a fresh snapshot. Called once per retry
    /// with the current edge-walk + DHT + DNS hints. *Replaces*, not
    /// appends — the topology may have churned between retries and
    /// stale gossip is worse than none. Dedups against tier 1 and
    /// itself; resets the cursor (tier-2 length changed, the old
    /// position is meaningless).
    pub(crate) fn add_known_addresses(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        self.known.clear();
        self.resolved.clear();
        for a in addrs {
            if self.known.len() >= MAX_EPHEMERAL {
                break;
            }
            if !self.recent.contains(&a) && !self.known.contains(&a) {
                self.known.push(a);
            }
        }
        self.cursor = 0;
    }

    /// Append late-arriving resolver results *without* resetting the
    /// cursor. They go into a trailing tier so growth never shifts
    /// already-walked positions; if the round had already returned
    /// `None` the new entries are picked up on the very next call.
    /// Cleared at the next [`Self::reset`] / [`Self::add_known_addresses`].
    pub(crate) fn extend_resolved(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        for a in addrs {
            if self.resolved.len() >= MAX_EPHEMERAL {
                break;
            }
            if !self.recent.contains(&a)
                && !self.known.contains(&a)
                && !self.config.contains(&a)
                && !self.resolved.contains(&a)
            {
                self.resolved.push(a);
            }
        }
    }

    /// `Address =` lines that need a real resolver. Empty for the
    /// common all-literal-IP config.
    #[must_use]
    pub(crate) fn unresolved_hosts(&self) -> Vec<(String, u16)> {
        self.hostnames.clone()
    }

    /// Next candidate address, or `None` when this round is
    /// exhausted. Never blocks.
    pub(crate) fn next_addr(&mut self) -> Option<SocketAddr> {
        let i = self.cursor;
        let r = self.recent.len();
        let k = r + self.known.len();
        let addr = if i < r {
            Some(self.recent[i])
        } else if i < k {
            Some(self.known[i - r])
        } else {
            // Tiers 3+4 dedup at read time: an addr already covered by
            // tiers 1/2 is skipped without burning a connect attempt.
            self.config
                .iter()
                .chain(&self.resolved)
                .filter(|a| !self.recent.contains(a) && !self.known.contains(a))
                .nth(i - k)
                .copied()
        };
        if addr.is_some() {
            self.cursor += 1;
        }
        addr
    }

    /// Record a working address. Moves it to the front of `recent`
    /// (or prepends if new), so the next round tries it first.
    /// Doesn't touch the cursor — callers reach this from a success
    /// path that will `reset` before dialling again.
    pub(crate) fn add_recent(&mut self, addr: SocketAddr) {
        self.recent.retain(|a| *a != addr);
        self.recent.insert(0, addr);
    }

    /// Start a fresh round. Tier 2 is *not* cleared here: the daemon
    /// always calls [`Self::add_known_addresses`] right after with a
    /// fresh snapshot, which both clears and refills it.
    pub(crate) fn reset(&mut self) {
        self.cursor = 0;
        self.resolved.clear();
    }

    /// Persist tier 1. Best-effort; the in-memory cache is
    /// authoritative for the running daemon.
    ///
    /// Atomic: write to a sibling temp file, `fsync`, `rename` over
    /// the target. A crash mid-write leaves either the old file or a
    /// stray `*.tmp` (a different inode; `load` only ever opens the
    /// final path) — never a truncated cache. `rename(2)` replaces a
    /// symlink rather than following it, so a remote-supplied node
    /// name can't redirect the write.
    ///
    /// # Errors
    /// `create_dir_all` / `open` / `write_all` / `rename` failures
    /// (read-only confbase, disk full).
    pub(crate) fn save(&self) -> io::Result<()> {
        match self.serialize() {
            Some((path, bytes)) => write_atomic(&path, &bytes),
            None => Ok(()),
        }
    }

    /// `(path, bytes)` for [`write_atomic`]; split so the event loop
    /// can ship the fsync+rename to the worker thread.
    #[must_use]
    pub(crate) fn serialize(&self) -> Option<(PathBuf, Vec<u8>)> {
        let path = self.path.clone()?;
        let mut buf = String::from(HEADER);
        buf.push('\n');
        for a in self.recent.iter().take(MAX_PERSISTED) {
            use std::fmt::Write as _;
            let _ = writeln!(buf, "{a}");
        }
        Some((path, buf.into_bytes()))
    }

    /// Detach from disk so `Drop` won't `save()`. Used after the
    /// serialized bytes have been handed to the worker thread.
    pub(crate) fn disarm(&mut self) {
        self.path = None;
    }
}

/// Crash-atomic write via `.tmp` sibling + `rename(2)`. Fixed suffix
/// (writes serialised on one thread → at most one stray temp/peer).
///
/// # Errors
/// `create_dir_all` / `open` / `write_all` / `rename` failures.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut tmp = path.to_path_buf().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, path)
}

/// Best-effort read. Missing file, wrong/absent header, unparseable
/// line → empty.
fn load(path: &Path) -> Vec<SocketAddr> {
    let Ok(f) = fs::File::open(path) else {
        return Vec::new();
    };
    let mut lines = BufReader::new(f).lines();
    match lines.next() {
        Some(Ok(h)) if h.trim() == HEADER => {}
        _ => return Vec::new(),
    }
    let mut out = Vec::new();
    for line in lines.take(2 * MAX_PERSISTED) {
        match line.map(|l| l.trim().parse()) {
            Ok(Ok(addr)) => out.push(addr),
            _ => return Vec::new(),
        }
    }
    out
}

impl Drop for AddressCache {
    /// Flush on drop. Can't propagate from `Drop`, so log at debug:
    /// a read-only confbase makes this fire on every outgoing teardown
    /// and the cache is purely an optimisation.
    fn drop(&mut self) {
        if let Err(e) = self.save() {
            log::debug!(target: "tincd::conn", "address cache save failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    use crate::testutil::tmpdir;

    fn drain(c: &mut AddressCache) -> Vec<SocketAddr> {
        std::iter::from_fn(|| c.next_addr()).collect()
    }

    #[test]
    fn add_recent_moves_to_front() {
        let mut c = AddressCache::new(vec![sa("10.0.0.1:655"), sa("10.0.0.2:655")]);
        c.add_recent(sa("10.0.0.9:655"));
        c.add_recent(sa("10.0.0.2:655")); // existing → rotate, no growth
        assert_eq!(
            c.recent,
            vec![sa("10.0.0.2:655"), sa("10.0.0.9:655"), sa("10.0.0.1:655")]
        );
    }

    #[test]
    fn roundtrip_file() {
        let tmp = tmpdir("roundtrip");
        {
            let mut c = AddressCache::open(&tmp, "bob", vec![("10.0.0.1".into(), 655)]);
            c.add_recent(sa("[::1]:655"));
            c.add_recent(sa("192.168.1.1:655"));
        }
        let mut c = AddressCache::open(&tmp, "bob", vec![("10.0.0.1".into(), 655)]);
        assert_eq!(
            drain(&mut c),
            vec![sa("192.168.1.1:655"), sa("[::1]:655"), sa("10.0.0.1:655")]
        );
    }

    #[test]
    fn cap_on_disk() {
        let tmp = tmpdir("cap");
        let path = tmp.join("addrcache").join("bob");
        {
            let mut c = AddressCache::open(&tmp, "bob", vec![]);
            for i in 0..10u8 {
                c.add_recent(sa(&format!("10.0.0.{i}:655")));
            }
            assert_eq!(c.recent.len(), 10);
        }
        let lines: Vec<_> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(lines.len(), 1 + MAX_PERSISTED);
        assert_eq!(lines[0], HEADER);
        assert_eq!(lines[1], "10.0.0.9:655");
        assert_eq!(lines[8], "10.0.0.2:655");
    }

    #[test]
    fn tier_order_and_known_replaces() {
        let mut c = AddressCache::new(vec![sa("10.0.0.1:655")]);
        c.config = vec![sa("10.0.0.3:655")];
        c.add_known_addresses([sa("10.0.0.2:655"), sa("10.0.0.1:655") /* dup */]);
        assert_eq!(
            drain(&mut c),
            vec![sa("10.0.0.1:655"), sa("10.0.0.2:655"), sa("10.0.0.3:655")]
        );
        // Second snapshot replaces, doesn't append; config tier persists.
        c.add_known_addresses([sa("10.0.0.9:655")]);
        assert_eq!(
            drain(&mut c),
            vec![sa("10.0.0.1:655"), sa("10.0.0.9:655"), sa("10.0.0.3:655")]
        );
    }

    /// Hostnames are not resolved inline; they're surfaced for the
    /// worker, and `next_addr` never blocks waiting on them.
    #[test]
    fn hostname_not_resolved_inline() {
        let tmp = tmpdir("host");
        let mut c = AddressCache::open(
            &tmp,
            "bob",
            vec![("10.0.0.1".into(), 655), ("bob.example.com".into(), 655)],
        );
        assert_eq!(c.unresolved_hosts(), vec![("bob.example.com".into(), 655)]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), None);
        // Late resolver result becomes visible mid-round.
        c.extend_resolved([sa("203.0.113.7:655")]);
        assert_eq!(c.next_addr(), Some(sa("203.0.113.7:655")));
        assert_eq!(c.next_addr(), None);
    }

    #[test]
    fn load_rejects_missing_or_wrong_header() {
        let tmp = tmpdir("hdr");
        let dir = tmp.join("addrcache");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a"), "10.0.0.9:655\n").unwrap();
        fs::write(dir.join("b"), "tinc-addrcache 2\n10.0.0.9:655\n").unwrap();
        assert!(load(&dir.join("a")).is_empty());
        assert!(load(&dir.join("b")).is_empty());
    }
}
