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
//! ## Deferred: lazy hostname resolve
//!
//! C `get_recent_address` (`:157-199`) calls `str2addrinfo` (which
//! calls `getaddrinfo`) for each `Address = bob.example.com 655`
//! line as the cursor reaches it — DNS at connect time, not config
//! load time. We take pre-resolved `SocketAddr`s only. Chunk 6's
//! `do_outgoing_connection` integration owns DNS.
//!
//! ## Tier structure: three vecs, not one
//!
//! C `get_recent_address` (`:119-215`) walks three sources in order:
//! cached (`:121`), edge-known (`:126-148` via `get_known_addresses`
//! `:31-65`), config (`:151-199`). C `reset_address_cache` (`:256-263`)
//! FREES `cache->ai` (the edge-known list) so the next dial re-walks
//! the graph — the topology may have changed between retries. We mirror
//! that: `known` is a separate vec that `add_known_addresses` replaces
//! wholesale; the daemon calls it on every `setup_outgoing_connection`
//! tick with a fresh edge-walk.
//!
//! `e->reverse->address` is what the FAR END reported in its `ADD_EDGE`:
//! if alice gossiped "bob→alice, addr=10.0.0.5:655", then walking bob's
//! edges gives `bob→alice` whose reverse is `alice→bob`, whose `address`
//! is 10.0.0.5 — where alice last saw bob. The graph already knows;
//! try those before DNS.
// TODO(chunk-6): lazy getaddrinfo for hostname `Address` lines (`:157-199`).

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// `address_cache.h:25`: `#define MAX_CACHED_ADDRESSES 8`. Only the
/// on-disk cache is capped — the in-memory `Vec` can hold more
/// (config might list 20 `Address` lines; we try them all, persist
/// the 8 most recent successes).
const MAX_CACHED_ADDRESSES: usize = 8;

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
    /// Tier 3 (`:151-199`): `Address =` config lines, pre-resolved.
    /// Static after `open()`.
    config: Vec<SocketAddr>,
    /// Index into the logical `cached ‖ known ‖ config` concatenation.
    /// `reset()` zeroes. C: `tried` (`:122`, `:243`).
    cursor: usize,
    /// `confbase/cache/NODE`. `None` = in-memory only (tests).
    cache_file: Option<PathBuf>,
}

impl AddressCache {
    /// `open_address_cache` (`:217-248`). Reads on-disk cache, then
    /// appends config addrs. The C reads the binary blob and
    /// validates `version == ADDRESS_CACHE_VERSION` and `used <=
    /// MAX_CACHED_ADDRESSES` (`:226`, `:244`); on either mismatch,
    /// `memset` to empty. We do the same: any parse failure → just
    /// the config addrs, no error. It's a cache.
    #[must_use]
    pub fn open(confbase: &Path, node_name: &str, config_addrs: Vec<SocketAddr>) -> Self {
        let cache_file = confbase.join("cache").join(node_name);
        let cached = Self::load(&cache_file);

        // Config addrs go AFTER cached-recent addrs (C: cached
        // tried first `:121`, config tried last `:151-199`).
        // Dedup: don't list a config addr that's already in the
        // recent cache. C handles this implicitly via `find_cached`
        // skip on the edge-addr path (`:137-139`); the config tier
        // (`:151-`) has no such skip but we dedup anyway — harmless,
        // saves a doomed connect attempt.
        let mut config = Vec::new();
        for a in config_addrs {
            if !cached.contains(&a) && !config.contains(&a) {
                config.push(a);
            }
        }

        Self {
            cached,
            known: Vec::new(),
            config,
            cursor: 0,
            cache_file: Some(cache_file),
        }
    }

    /// In-memory only. Tests; also useful if you have addrs from
    /// some other source and don't want disk I/O. The single-vec
    /// constructor predates the tier split: everything goes in
    /// `cached` (so `add_recent` and `save` work as before).
    #[must_use]
    pub fn new(addrs: Vec<SocketAddr>) -> Self {
        Self {
            cached: addrs,
            known: Vec::new(),
            config: Vec::new(),
            cursor: 0,
            cache_file: None,
        }
    }

    /// `get_known_addresses` injection point (`:31-65`, `:126-148`).
    /// Replaces tier 2 wholesale with a fresh edge-walk.
    ///
    /// **REPLACES**, not appends: C `reset_address_cache:261-263`
    /// frees `cache->ai` so the next `get_recent_address` calls
    /// `get_known_addresses(cache->node)` from scratch (`:128-129`).
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
            if !self.cached.contains(&a) && !self.known.contains(&a) {
                self.known.push(a);
            }
        }
        self.cursor = 0;
    }

    /// Best-effort read. Missing file, unparseable line → empty.
    /// C `:226`: `if(!fp || fread(...) != 1 || version != ...) memset(&data, 0, ...)`.
    fn load(path: &Path) -> Vec<SocketAddr> {
        let Ok(f) = fs::File::open(path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in BufReader::new(f).lines() {
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
    /// when exhausted. The C does a complicated three-phase walk
    /// (cached → edge-known → config-with-getaddrinfo) with `tried`
    /// tracking which phase. We pre-built each tier so this is just
    /// an index into the logical concatenation.
    pub fn next_addr(&mut self) -> Option<SocketAddr> {
        let i = self.cursor;
        let c = self.cached.len();
        let k = c + self.known.len();
        let a = if i < c {
            self.cached.get(i)
        } else if i < k {
            self.known.get(i - c)
        } else {
            self.config.get(i - k)
        }
        .copied();
        if a.is_some() {
            self.cursor += 1;
        }
        a
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
        // C `:86-89` `find_cached` walks `data.address[]` only (the
        // on-disk cache). We tier-split now so this matches exactly:
        // dedup within tier 1, don't touch tiers 2/3.
        self.cached.retain(|a| *a != addr);
        self.cached.insert(0, addr);
        // Cursor is now stale. The C doesn't reset `tried` here
        // either (`:84-116` touches `data` only, not `tried`); the
        // call site in `finish_connecting` (`net_socket.c`) doesn't
        // call `get_recent_address` again before `reset`. Match that.
    }

    /// `reset_address_cache` (`:251-266`). Cursor to 0. Called on
    /// retry (the `retry_outgoing` exponential-backoff timer).
    pub fn reset(&mut self) {
        self.cursor = 0;
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
        let Some(path) = &self.cache_file else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut buf = Vec::new();
        // Only tier 1 persists (C `data.address[]`). Tiers 2/3 are
        // regenerated from graph/config at next `open`.
        for a in self.cached.iter().take(MAX_CACHED_ADDRESSES) {
            writeln!(buf, "{a}")?;
        }
        fs::write(path, buf)
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
            log::warn!(target: "tincd::conn", "address cache save failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
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

    #[test]
    fn next_advances() {
        let mut c = AddressCache::new(vec![
            sa("10.0.0.1:655"),
            sa("10.0.0.2:655"),
            sa("10.0.0.3:655"),
        ]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.2:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.3:655")));
        assert_eq!(c.next_addr(), None);
        assert_eq!(c.next_addr(), None);
    }

    #[test]
    fn reset_rewinds() {
        let mut c = AddressCache::new(vec![sa("10.0.0.1:655"), sa("10.0.0.2:655")]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.2:655")));
        assert_eq!(c.next_addr(), None);
        c.reset();
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
    }

    #[test]
    fn add_recent_prepends() {
        let mut c = AddressCache::new(vec![sa("10.0.0.1:655")]);
        c.add_recent(sa("10.0.0.9:655"));
        c.reset();
        assert_eq!(c.next_addr(), Some(sa("10.0.0.9:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), None);
    }

    #[test]
    fn add_recent_dedups() {
        let mut c = AddressCache::new(vec![sa("10.0.0.1:655")]);
        c.add_recent(sa("10.0.0.9:655"));
        c.add_recent(sa("10.0.0.9:655"));
        // Two adds of the same addr: list grows by one, not two.
        assert_eq!(c.cached.len(), 2);
        c.reset();
        assert_eq!(c.next_addr(), Some(sa("10.0.0.9:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), None);
    }

    #[test]
    fn add_recent_moves_to_front() {
        // C `:86-104`: `find_cached` returns position, `memmove`
        // shifts [0..pos) right by one, write to [0]. Net: rotate.
        let mut c = AddressCache::new(vec![
            sa("10.0.0.1:655"),
            sa("10.0.0.2:655"),
            sa("10.0.0.3:655"),
        ]);
        c.add_recent(sa("10.0.0.3:655")); // was at position 2
        assert_eq!(c.cached.len(), 3); // same length
        c.reset();
        assert_eq!(c.next_addr(), Some(sa("10.0.0.3:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), Some(sa("10.0.0.2:655")));
    }

    #[test]
    fn roundtrip_file() {
        let tmp = tmpdir("roundtrip");
        {
            let mut c = AddressCache::open(&tmp, "bob", vec![sa("10.0.0.1:655")]);
            c.add_recent(sa("[::1]:655"));
            c.add_recent(sa("192.168.1.1:655"));
            // Drop saves.
        }
        // Reopen: cached addrs first, config addr deduped if
        // already cached, appended if not.
        let mut c = AddressCache::open(&tmp, "bob", vec![sa("10.0.0.1:655")]);
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
        // C `:226`: `!fp` → memset. No cache dir at all.
        let tmp = tmpdir("missing");
        let mut c = AddressCache::open(&tmp, "alice", vec![sa("10.0.0.1:655")]);
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
        let mut c = AddressCache::open(&tmp, "bob", vec![sa("10.0.0.3:655")]);
        c.add_known_addresses([sa("10.0.0.2:655")]);
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655"))); // cached
        assert_eq!(c.next_addr(), Some(sa("10.0.0.2:655"))); // known
        assert_eq!(c.next_addr(), Some(sa("10.0.0.3:655"))); // config
        assert_eq!(c.next_addr(), None);
    }

    /// C `:40-50` (intra-walk dedup) and `:137-139` (`find_cached`
    /// skip): edge-known addrs dedup vs themselves and vs tier 1.
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

    /// C `:108-116` only writes `data.address[]`. Edge-known addrs
    /// are volatile (the graph regenerates them); don't persist.
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

    #[test]
    fn load_garbage_is_empty() {
        // C-written sockaddr_storage binary blob hits this path.
        // C `:226`: version mismatch → memset.
        let tmp = tmpdir("garbage");
        let dir = tmp.join("cache");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bob"), b"\x01\x00\x00\x00garbage\xff\xfe").unwrap();
        let mut c = AddressCache::open(&tmp, "bob", vec![sa("10.0.0.1:655")]);
        // Only the config addr survives.
        assert_eq!(c.next_addr(), Some(sa("10.0.0.1:655")));
        assert_eq!(c.next_addr(), None);
    }
}
