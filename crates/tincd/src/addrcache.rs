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
//! C `get_recent_address` (`:151-199`) calls `str2addrinfo` (which
//! calls `getaddrinfo`) for each `Address = bob.example.com 655`
//! line as the cursor reaches it — DNS at connect time, not config
//! load time. We take pre-resolved `SocketAddr`s only. Chunk 6's
//! `do_outgoing_connection` integration owns DNS.
// TODO(chunk6): lazy getaddrinfo for hostname `Address` lines (`:151-199`).

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
/// `config_tree*` for lazy walk. We flatten: one `Vec`, one cursor.
pub struct AddressCache {
    /// Addresses to try, in order. Recently-successful first
    /// (prepended by `add_recent`); config `Address` lines after.
    addrs: Vec<SocketAddr>,
    /// Index of next addr to return. `reset()` zeroes. C: `tried`
    /// (`:122`, `:243`).
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
        let mut addrs = Self::load(&cache_file);

        // Config addrs go AFTER cached-recent addrs (C: cached
        // tried first `:121`, config tried last `:151-199`).
        // Dedup: don't list a config addr that's already in the
        // recent cache. C handles this implicitly via `find_cached`
        // skip on the edge-addr path (`:137-139`).
        for a in config_addrs {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }

        Self {
            addrs,
            cursor: 0,
            cache_file: Some(cache_file),
        }
    }

    /// In-memory only. Tests; also useful if you have addrs from
    /// some other source and don't want disk I/O.
    #[must_use]
    pub fn new(addrs: Vec<SocketAddr>) -> Self {
        Self {
            addrs,
            cursor: 0,
            cache_file: None,
        }
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
    /// tracking which phase. We flattened at `open()` time so this
    /// is just an index bump.
    pub fn next_addr(&mut self) -> Option<SocketAddr> {
        let a = self.addrs.get(self.cursor).copied();
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
        self.addrs.retain(|a| *a != addr);
        self.addrs.insert(0, addr);
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
        for a in self.addrs.iter().take(MAX_CACHED_ADDRESSES) {
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
        assert_eq!(c.addrs.len(), 2);
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
        assert_eq!(c.addrs.len(), 3); // same length
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
            assert_eq!(c.addrs.len(), 10); // in-memory: all 10
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
