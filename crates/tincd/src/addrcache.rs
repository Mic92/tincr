//! Per-node address cache (`address_cache.c`, 284 LOC).
//!
//! `do_outgoing_connection` walks this when dialing peer `bob`: try
//! each address in order, advance on failure, prepend on success.
//! The C interleaves three sources — on-disk recent cache (`:121`),
//! edge-tree known addrs (`:126-148`), and lazily-resolved `Address`
//! config lines (`:151-199`). We collapse to one `Vec<SocketAddr>`
//! built at `open()` time; the cursor walks it.
//!
//! ## On-disk format: text, not `sockaddr_storage`
//!
//! The C cache file (`:108-114`, `:221-227`) is a raw `fwrite` of
//! `struct { uint32_t version; uint32_t used; sockaddr_t addr[8]; }`.
//! `sockaddr_in`/`sockaddr_in6` layout is platform-specific (BSD has
//! `sin_len`, Linux doesn't; padding differs). A C-tincd cache file
//! on FreeBSD won't parse on Linux *with the same C code* — tinc
//! just never noticed because the file is per-host.
//!
//! We write one address per line in `SocketAddr::Display` form
//! (`10.0.0.1:655`, `[::1]:655`). Human-readable, portable,
//! `from_str` is the parser. **STRICTER**: a C-written cache file
//! won't parse here. That's fine — it's a *cache*, regenerated from
//! config + the first successful connection. Loss is one extra
//! connect attempt on first run after switching binaries.
//!
//! ## Lazy hostname resolve (`:157-199`)
//!
//! `get_recent_address` calls `getaddrinfo` for each `Address =
//! bob.example.com 655` line **as the cursor reaches
//! it** — DNS at connect time, not config load time. Tier 3 stores
//! unresolved `(host, port)` pairs; [`AddressCache::next_addr`]
//! resolves on demand. The resolve is **blocking** (so
//! is C's). Win over eager: `open()` doesn't block, AND each retry
//! round (after `reset()`) re-resolves, so dynamic DNS picks up the
//! new IP. Per-round resolve cache: each `Address` line resolves
//! once per round, results buffered until `reset()`.
//!
//! ## Tier structure: three vecs, not one
//!
//! `get_recent_address` walks three sources in order: cached,
//! edge-known, config. `reset_address_cache` FREES `cache->ai` (the
//! edge-known list) so the next dial re-walks the graph — the
//! topology may have changed between retries. We mirror
//! that: `known` is a separate vec that `add_known_addresses` replaces
//! wholesale; the daemon calls it on every `setup_outgoing_connection`
//! tick with a fresh edge-walk.
//!
//! `e->reverse->address` is what the FAR END reported in its `ADD_EDGE`:
//! if alice gossiped "bob→alice, addr=10.0.0.5:655", then walking bob's
//! edges gives `bob→alice` whose reverse is `alice→bob`, whose `address`
//! is 10.0.0.5 — where alice last saw bob. The graph already knows;
//! try those before DNS.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

/// `address_cache.h:25`: `#define MAX_CACHED_ADDRESSES 8`. Only the
/// on-disk cache is capped — the in-memory `Vec` can hold more
/// (config might list 20 `Address` lines; we try them all, persist
/// the 8 most recent successes).
const MAX_CACHED_ADDRESSES: usize = 8;
/// Bound the in-memory `known`/`config_resolved` lists; keeps the
/// O(n) dedup scans cheap regardless of gossip/DNS fan-out.
const MAX_KNOWN_ADDRESSES: usize = 8 * MAX_CACHED_ADDRESSES;

/// `address_cache_t` (`address_cache.h:29-42`). The C struct holds a
/// fixed-size `sockaddr_t[8]` plus the `addrinfo*` chain plus
/// `config_tree*` for lazy walk. We split into the same three tiers
/// the C walks: `cached` → `known` → `config`. One cursor over the
/// concatenation.
pub struct AddressCache {
    /// Tier 1 (`:121-123`): on-disk recent cache + `add_recent`
    /// prepends. Only this tier is persisted (`:108-116`).
    cached: Vec<SocketAddr>,
    /// Tier 2 (`:126-148`, `get_known_addresses` `:31-65`): edge-
    /// derived. Volatile — C frees on reset (`:261-263`) so the next
    /// dial re-walks `n->edge_tree`. We replace via
    /// [`add_known_addresses`](Self::add_known_addresses).
    known: Vec<SocketAddr>,
    /// Tier 3 source: `Address =` config lines, **unresolved**.
    /// Static after `open()`.
    config: Vec<(String, u16)>,
    /// Tier 3 resolved buffer. `next_addr` extends this lazily as the
    /// cursor walks into tier 3 (one `to_socket_addrs()` per
    /// `config[config_idx]` line). C's `cache->ai` (`:159-184`).
    /// Cleared on `reset()` → fresh DNS each retry round.
    config_resolved: Vec<SocketAddr>,
    /// Next `config[]` index to resolve. C: implicit in the
    /// `lookup_config_next` walk (`:194`).
    config_idx: usize,
    /// Index into the logical `cached ‖ known ‖ config_resolved`
    /// concatenation. `reset()` zeroes. C: `tried` (`:122`, `:243`).
    cursor: usize,
    /// `<cache_dir>/NODE`. `None` = in-memory only (tests).
    cache_file: Option<PathBuf>,
}

/// Pick the directory for the on-disk cache. C tinc hard-codes
/// `confbase/cache/` (`address_cache.c:108`). On NixOS confbase is a
/// read-only store path and tincd runs unprivileged with systemd
/// `StateDirectory=` — use that when set. No writability probe:
/// `open()` for the initial `ConnectTo` peers runs pre-`drop_privs`
/// where `CAP_DAC_OVERRIDE` makes `access(W_OK)` lie. The env var
/// being set IS the operator signal that confbase is managed; bare
/// `tincd -n foo` / chroot / BSD have no `$STATE_DIRECTORY` and keep
/// the C layout.
fn resolve_cache_dir(confbase: &Path, state_dir: Option<&Path>) -> PathBuf {
    state_dir.unwrap_or(confbase).join("cache")
}

impl AddressCache {
    /// `open_address_cache` (`:217-248`). Reads on-disk cache, then
    /// appends config addrs. The C reads the binary blob and
    /// validates `version == ADDRESS_CACHE_VERSION` and `used <=
    /// MAX_CACHED_ADDRESSES` (`:226`, `:244`); on either mismatch,
    /// `memset` to empty. We do the same: any parse failure → just
    /// the config addrs, no error. It's a cache.
    #[must_use]
    pub fn open(confbase: &Path, node_name: &str, config_addrs: Vec<(String, u16)>) -> Self {
        let state_dir = std::env::var_os("STATE_DIRECTORY").map(PathBuf::from);
        let cache_file = resolve_cache_dir(confbase, state_dir.as_deref()).join(node_name);
        let cached = Self::load(&cache_file);

        // Config addrs are unresolved (host, port) pairs; dedup vs
        // tier 1 happens at RESOLVE time in `next_addr` (we can't
        // compare a hostname to a `SocketAddr` here). The C config
        // tier (`:151-199`) has no dedup either — it just walks
        // `lookup_config_next`. Dedup the (host, port) pairs against
        // each other to skip literal duplicate `Address =` lines.
        let mut config = Vec::new();
        for hp in config_addrs {
            if !config.contains(&hp) {
                config.push(hp);
            }
        }

        Self {
            cached,
            known: Vec::new(),
            config,
            config_resolved: Vec::new(),
            config_idx: 0,
            cursor: 0,
            cache_file: Some(cache_file),
        }
    }

    /// In-memory only. Tests; also useful if you have addrs from
    /// some other source and don't want disk I/O. The single-vec
    /// constructor predates the tier split: everything goes in
    /// `cached` (so `add_recent` and `save` work as before).
    #[must_use]
    pub const fn new(addrs: Vec<SocketAddr>) -> Self {
        Self {
            cached: addrs,
            known: Vec::new(),
            config: Vec::new(),
            config_resolved: Vec::new(),
            config_idx: 0,
            cursor: 0,
            cache_file: None,
        }
    }

    /// `get_known_addresses` injection point (`:31-65`, `:126-148`).
    /// Replaces tier 2 wholesale with a fresh edge-walk.
    ///
    /// **REPLACES**, not appends: `reset_address_cache` frees
    /// `cache->ai` so the next `get_recent_address` calls
    /// `get_known_addresses(cache->node)` from scratch.
    /// The graph may have churned between retries; stale gossip is
    /// worse than none. Caller (`setup_outgoing_connection`) walks
    /// the live graph each tick.
    ///
    /// Dedup vs tier 1 (`:137-139`: `if(find_cached(...) != NOT_
    /// CACHED) continue`). The C also dedups within the edge-walk
    /// itself (`:40-50`, the `bool found` loop).
    ///
    /// Cursor reset: tier 2's length changed, so any live cursor is
    /// stale. C calls this from `reset_address_cache` which already
    /// zeroed `tried`; do the same.
    pub fn add_known_addresses(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        self.known.clear();
        for a in addrs {
            if self.known.len() >= MAX_KNOWN_ADDRESSES {
                break;
            }
            if !self.cached.contains(&a) && !self.known.contains(&a) {
                self.known.push(a);
            }
        }
        self.cursor = 0;
    }

    /// Best-effort read. Missing file, unparseable line → empty.
    fn load(path: &Path) -> Vec<SocketAddr> {
        let Ok(f) = fs::File::open(path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // We never write more than MAX_CACHED_ADDRESSES; ignore excess on read.
        for line in BufReader::new(f).lines().take(2 * MAX_CACHED_ADDRESSES) {
            let Ok(line) = line else { return Vec::new() };
            let Ok(addr) = line.trim().parse() else {
                // C-written binary garbage hits here. Drop the lot,
                // same as the C version-mismatch path.
                return Vec::new();
            };
            out.push(addr);
        }
        out
    }

    /// `get_recent_address` (`:119-215`). Returns next addr; `None`
    /// when exhausted. Three-phase walk: cached → edge-known →
    /// config-with-getaddrinfo. Tiers 1/2 are pre-built; tier 3
    /// resolves lazily HERE (`:157-199`: `str2addrinfo` per
    /// `Address` line as the cursor reaches it).
    ///
    /// **Blocking**: tier-3 entry may call `to_socket_addrs()`
    /// (= `getaddrinfo`). Same as C. Don't call from a hot loop
    /// expecting sub-ms latency.
    pub fn next_addr(&mut self) -> Option<SocketAddr> {
        let cur = self.cursor;
        let n_cached = self.cached.len();
        let n_known = n_cached + self.known.len();
        let addr = if cur < n_cached {
            self.cached.get(cur).copied()
        } else if cur < n_known {
            self.known.get(cur - n_cached).copied()
        } else {
            // Tier 3. Walk `Address =` lines, resolve each via
            // `getaddrinfo`, return one addr per call. The resolved
            // chain is kept until reset so we
            // don't re-resolve mid-round. `config_resolved` is that
            // chain; `config_idx` is the `lookup_config_next` cursor.
            let want = cur - n_known;
            // Resolve more `Address` lines until we have addr `want` (or
            // run out of lines). Each line may yield 0 (NXDOMAIN), 1,
            // or several (v4+v6) addrs. Dups (vs tiers 1/2/3-so-far)
            // just don't push — the loop keeps going. C's config tier
            // doesn't dedup (`:151-199` has no `find_cached`); we do,
            // harmlessly, saves a doomed connect.
            while want >= self.config_resolved.len() && self.config_idx < self.config.len() {
                let (host, port) = &self.config[self.config_idx];
                self.config_idx += 1;
                // `getaddrinfo` failure just moves to the next
                // config line.
                match (host.as_str(), *port).to_socket_addrs() {
                    Ok(iter) => {
                        for a in iter {
                            if self.config_resolved.len() >= MAX_KNOWN_ADDRESSES {
                                break;
                            }
                            if !self.cached.contains(&a)
                                && !self.known.contains(&a)
                                && !self.config_resolved.contains(&a)
                            {
                                self.config_resolved.push(a);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(target: "tincd::conn",
                                   "Address = {host} {port}: {e}");
                    }
                }
            }
            self.config_resolved.get(want).copied()
        };
        if addr.is_some() {
            self.cursor += 1;
        }
        addr
    }

    /// `add_recent_address` (`:84-116`). Prepend a working address.
    /// Called when a connection SUCCEEDS — this is the learning.
    ///
    /// Dedup (`:86-89`, `:96-102`): if `addr` is already in the
    /// list, REMOVE it first, then prepend. Net effect: move to
    /// front. The C's `:89` `if(pos == 0) return` early-out is
    /// covered: `retain` then `insert(0)` of the same addr is a
    /// no-op on order.
    ///
    /// The C also writes to disk here (`:108-116`). We defer to
    /// `save()` / `Drop` — one write at end-of-life, not one per
    /// successful connection. Slightly different crash behavior
    /// (C survives a crash mid-session with partial learning; we
    /// don't); fine for a cache.
    pub fn add_recent(&mut self, addr: SocketAddr) {
        // `find_cached` walks `data.address[]` only (the on-disk
        // cache). We tier-split so this matches exactly: dedup
        // within tier 1, don't touch tiers 2/3.
        self.cached.retain(|a| *a != addr);
        self.cached.insert(0, addr);
        // Cursor is now stale. The C doesn't reset `tried` here
        // either (`:84-116` touches `data` only, not `tried`); the
        // call site in `finish_connecting` (`net_socket.c`) doesn't
        // call `get_recent_address` again before `reset`. Match that.
    }

    /// `reset_address_cache` (`:251-266`). Cursor to 0. Called on
    /// retry (the `retry_outgoing` exponential-backoff timer).
    /// Frees the resolved-addrinfo chain so the next round
    /// re-resolves. Dynamic DNS: if `bob.
    /// example.com` changed IPs between retries, we pick that up.
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.config_resolved.clear();
        self.config_idx = 0;
    }

    /// Persist to `confbase/cache/NODE`. C does this inline in
    /// `add_recent_address` (`:108-116`); we batch.
    ///
    /// Only the first `MAX_CACHED_ADDRESSES` go to disk — the C
    /// struct is fixed-size `sockaddr_t[8]`. The in-memory tail
    /// (config addrs that never succeeded) doesn't need persisting:
    /// it's reloaded from config next time.
    ///
    /// # Errors
    /// Propagates I/O errors from `create_dir_all` / `write`.
    /// `None` cache file (in-memory mode) → `Ok(())`.
    pub fn save(&self) -> io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let Some(path) = &self.cache_file else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut buf = Vec::new();
        // Only tier 1 persists (`data.address[]`). Tiers 2/3 are
        // regenerated from graph/config at next `open`.
        for a in self.cached.iter().take(MAX_CACHED_ADDRESSES) {
            writeln!(buf, "{a}")?;
        }
        // O_NOFOLLOW: cache filename is a remote-supplied node name.
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)?
            .write_all(&buf)
    }
}

impl Drop for AddressCache {
    /// `close_address_cache` (`:268-278`). The C just frees; the
    /// disk write already happened in `add_recent_address`. We
    /// deferred the write, so do it now. Can't propagate from
    /// `Drop` — log it. Target `tincd::conn` matches C's
    /// `DEBUG_CONNECTIONS` (`:93`).
    fn drop(&mut self) {
        if let Err(e) = self.save() {
            // Debug, not warn: read-only confdir (NixOS store) makes
            // this fire on every outgoing retry. The cache is an
            // optimisation; losing it costs one extra connect().
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

    fn cfg(host: &str, port: u16) -> (String, u16) {
        (host.to_string(), port)
    }

    /// Unique tempdir per test. Workspace convention: thread id in
    /// name, no `tempfile` dep. Cleanup is best-effort (these tests
    /// don't share state across runs, and `/tmp` is tmpfs).
    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tincd-addrcache-{tag}-{:?}",
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Drain the cache via `next_addr` until `None`.
    fn drain(c: &mut AddressCache) -> Vec<SocketAddr> {
        std::iter::from_fn(|| c.next_addr()).collect()
    }

    #[test]
    fn cursor_walk_and_reset() {
        let addrs = vec![sa("10.0.0.1:655"), sa("10.0.0.2:655"), sa("10.0.0.3:655")];
        let mut c = AddressCache::new(addrs.clone());
        assert_eq!(drain(&mut c), addrs);
        assert_eq!(c.next_addr(), None); // stays exhausted
        c.reset();
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
    }

    /// `add_recent_address` (`:84-116`): new addr prepends; existing
    /// addr rotates to front without growing the list.
    #[test]
    fn add_recent_prepend_and_move_to_front() {
        let mut c = AddressCache::new(vec![sa("10.0.0.1:655"), sa("10.0.0.2:655")]);
        c.add_recent(sa("10.0.0.9:655")); // new → prepend
        c.add_recent(sa("10.0.0.2:655")); // existing → rotate, no growth
        assert_eq!(
            c.cached,
            vec![sa("10.0.0.2:655"), sa("10.0.0.9:655"), sa("10.0.0.1:655")]
        );
    }

    #[test]
    fn roundtrip_file() {
        let tmp = tmpdir("roundtrip");
        {
            let mut c = AddressCache::open(&tmp, "bob", vec![cfg("10.0.0.1", 655)]);
            c.add_recent(sa("[::1]:655"));
            c.add_recent(sa("192.168.1.1:655"));
            // Drop saves.
        }
        // Reopen: cached addrs first, config addr deduped if
        // already cached, appended if not.
        let mut c = AddressCache::open(&tmp, "bob", vec![cfg("10.0.0.1", 655)]);
        assert_eq!(c.next_addr(), Some(sa("192.168.1.1:655")));
        assert_eq!(c.next_addr(), Some(sa("[::1]:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), None);
    }

    #[test]
    fn cap_on_disk() {
        // `address_cache.h:25`: only 8 persisted. In-memory uncapped.
        let tmp = tmpdir("cap");
        let path = tmp.join("cache").join("bob");
        {
            let mut c = AddressCache::open(&tmp, "bob", vec![]);
            for i in 0..10u8 {
                // add_recent prepends, so final order is 9,8,7,...,0.
                c.add_recent(sa(&format!("10.0.0.{i}:655")));
            }
            assert_eq!(c.cached.len(), 10); // in-memory: all 10
            c.save().unwrap();
        }
        let body = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().collect();
        assert_eq!(lines.len(), 8);
        // Most-recent-first: 9 was added last, prepended last.
        assert_eq!(lines[0], "10.0.0.9:655");
        assert_eq!(lines[7], "10.0.0.2:655");
    }

    #[test]
    fn open_missing_file_is_config_only() {
        // No cache dir at all → empty cache.
        let tmp = tmpdir("missing");
        let mut c = AddressCache::open(&tmp, "alice", vec![cfg("10.0.0.1", 655)]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), None);
    }

    /// `get_known_addresses` (`:31-65`, `:126-148`): tier 2 sits
    /// between cached and config. Replaces wholesale each call (C
    /// frees on reset, `:261-263`).
    #[test]
    fn known_addresses_tier_order() {
        let tmp = tmpdir("known-tier");
        // Seed disk cache (tier 1).
        {
            let mut c = AddressCache::open(&tmp, "bob", vec![]);
            c.add_recent(sa("10.0.0.1:655"));
        }
        // Reopen with config (tier 3); inject edge-known (tier 2).
        let mut c = AddressCache::open(&tmp, "bob", vec![cfg("10.0.0.3", 655)]);
        c.add_known_addresses([sa("10.0.0.2:655")]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655"))); // cached
        assert_eq!(c.next_addr(), Some(sa("10.0.0.2:655"))); // known
        assert_eq!(c.next_addr(), Some(sa("10.0.0.3:655"))); // config
        assert_eq!(c.next_addr(), None);
    }

    /// Edge-known addrs dedup vs themselves and vs tier 1.
    #[test]
    fn known_addresses_dedup() {
        let mut c = AddressCache::new(vec![sa("10.0.0.1:655")]);
        c.add_known_addresses([
            sa("10.0.0.2:655"),
            sa("10.0.0.1:655"), // dup vs cached — skipped (`:137-139`)
            sa("10.0.0.2:655"), // dup vs self — skipped (`:40-50`)
            sa("10.0.0.3:655"),
        ]);
        assert_eq!(c.known, vec![sa("10.0.0.2:655"), sa("10.0.0.3:655")]);
    }

    /// `reset_address_cache:261-263`: `if(cache->ai) free_known_
    /// addresses(cache->ai)`. Next dial re-walks the graph; topology
    /// may have churned. Second call REPLACES, doesn't append.
    #[test]
    fn known_addresses_replaces() {
        let mut c = AddressCache::new(vec![]);
        c.add_known_addresses([sa("10.0.0.1:655"), sa("10.0.0.2:655")]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        // Graph churned: alice left, dave gossiped a new addr.
        c.add_known_addresses([sa("10.0.0.9:655")]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.9:655")));
        assert_eq!(c.next_addr(), None);
        // Empty walk (node has no edges) clears tier 2 entirely.
        c.add_known_addresses(std::iter::empty());
        assert_eq!(c.next_addr(), None);
    }

    /// Only `data.address[]` is written. Edge-known addrs are
    /// volatile (the graph regenerates them); don't persist.
    #[test]
    fn known_addresses_not_persisted() {
        let tmp = tmpdir("known-nopersist");
        let path = tmp.join("cache").join("bob");
        {
            let mut c = AddressCache::open(&tmp, "bob", vec![]);
            c.add_known_addresses([sa("10.0.0.99:655")]);
            c.add_recent(sa("10.0.0.1:655"));
        }
        let body = fs::read_to_string(&path).unwrap();
        assert_eq!(body.trim(), "10.0.0.1:655");
    }

    /// Two `Address =` lines: tier 3 yields both exactly once per
    /// round; `reset()` clears the resolve buffer so the next round
    /// re-resolves (dynamic DNS pickup).
    #[test]
    fn lazy_resolve_two_lines_once_per_round() {
        let mut c = AddressCache::new(vec![]);
        c.config = vec![cfg("127.0.0.1", 655), cfg("127.0.0.2", 655)];
        let want = vec![sa("127.0.0.1:655"), sa("127.0.0.2:655")];
        assert_eq!(drain(&mut c), want);
        c.reset();
        assert_eq!(c.config_resolved.len(), 0);
        assert_eq!(c.config_idx, 0);
        assert_eq!(drain(&mut c), want);
    }

    /// Resolve dedup: a config addr that's already in tier 1 (cached)
    /// is skipped at resolve time. The cursor doesn't drift.
    #[test]
    fn lazy_resolve_dedup_vs_cached() {
        let mut c = AddressCache::new(vec![sa("127.0.0.1:655")]);
        c.config = vec![cfg("127.0.0.1", 655), cfg("127.0.0.2", 655)];
        // Tier 1: 127.0.0.1. Tier 3: 127.0.0.1 (dup, skipped) then 127.0.0.2.
        assert_eq!(c.next_addr(), Some(sa("127.0.0.1:655")));
        assert_eq!(c.next_addr(), Some(sa("127.0.0.2:655")));
        assert_eq!(c.next_addr(), None);
    }

    /// `$STATE_DIRECTORY` set → always used, regardless of confbase
    /// writability (the probe lied under `CAP_DAC_OVERRIDE` pre-
    /// `drop_privs`). Unset → C-compatible `confbase/cache/`.
    #[test]
    fn resolve_cache_dir_prefers_state_dir() {
        let conf = Path::new("/etc/tinc/net");
        let state = Path::new("/var/lib/tinc/net");
        assert_eq!(resolve_cache_dir(conf, Some(state)), state.join("cache"));
        assert_eq!(resolve_cache_dir(conf, None), conf.join("cache"));
    }

    /// Regression: read-only confbase, no state dir (non-systemd
    /// unprivileged run). `save()` errors but `Drop` swallows it at
    /// debug — no panic, no warn-spam.
    #[test]
    fn drop_swallows_eacces_on_readonly_confbase() {
        use std::os::unix::fs::PermissionsExt;
        let conf = tmpdir("ro-conf");
        fs::set_permissions(&conf, fs::Permissions::from_mode(0o555)).unwrap();
        {
            let mut c = AddressCache::new(vec![]);
            c.cache_file = Some(resolve_cache_dir(&conf, None).join("bob"));
            c.add_recent(sa("10.0.0.1:655"));
            assert!(c.save().is_err()); // EACCES surfaces from save()…
        } // …but Drop swallows it.
        fs::set_permissions(&conf, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn load_garbage_is_empty() {
        // Upstream-written sockaddr_storage binary blob hits this
        // path. Version mismatch → empty.
        let tmp = tmpdir("garbage");
        let dir = tmp.join("cache");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bob"), b"\x01\x00\x00\x00garbage\xff\xfe").unwrap();
        let mut c = AddressCache::open(&tmp, "bob", vec![cfg("10.0.0.1", 655)]);
        // Only the config addr survives.
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), None);
    }
}
