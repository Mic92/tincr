//! Off-thread `getaddrinfo`.
//!
//! `do_outgoing_connection` runs on the epoll thread via the
//! `RetryOutgoing` timer. libc `getaddrinfo` blocks for its full
//! resolver timeout (glibc default 5 s per server, 30 s with a broken
//! `resolv.conf`). One slow lookup parks the whole reactor — same
//! stall class as the DHT-publish bug fixed in `682eed0a`.
//!
//! [`DnsWorker`] is the same shape as `discovery::DhtWorker`: a named
//! `std::thread` with a flume request channel in and a result channel
//! out. The epoll thread only does non-blocking `send` / `try_iter`.
//! A *separate* thread (not folded into `dht-worker`): a BEP 44
//! `put_mutable` is seconds-long; a DNS lookup queued behind one would
//! inherit that latency. One extra parked thread is free.
//!
//! ## No reactor wakeup
//!
//! Results are drained from `on_periodic_tick` (5 s cadence) — same as
//! `DhtWorker`. Outgoing retries are seconds-granular (`bump_timeout`
//! starts at +5 s), so a dedicated `eventfd` wake would only shave the
//! first connect on a hostname-only `Address=` by a few seconds. Not
//! worth the extra fd in the loop; documented trade-off.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};

/// What a resolve is *for*. The worker doesn't care — it just runs
/// `getaddrinfo` over `hosts` — but the daemon needs to route the
/// result, and the inflight gate keys on it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsTag {
    /// Tier-3 addrcache resolve for an outgoing to this peer.
    Outgoing(String),
    /// SOCKS/HTTP proxy host. At most one per daemon.
    Proxy,
}

/// Work item. One request carries *all* hostnames for its tag so the
/// result replaces the daemon-side cache wholesale (no cross-round
/// accumulation of stale addrs).
#[derive(Debug)]
pub struct DnsReq {
    pub tag: DnsTag,
    pub hosts: Vec<(String, u16)>,
}

/// Resolve result. `addrs` empty ⇒ every lookup failed (NXDOMAIN /
/// timeout); the worker already logged the per-host error.
#[derive(Debug)]
pub struct DnsRes {
    pub tag: DnsTag,
    pub addrs: Vec<SocketAddr>,
}

/// See module doc. Dropping `req_tx` makes the worker's `recv()` return
/// `Disconnected` → thread exits → `_join` is collected at process exit
/// (we don't `.join()` on `Drop`; a hung `getaddrinfo` would wedge
/// shutdown).
pub struct DnsWorker {
    req_tx: flume::Sender<DnsReq>,
    res_rx: flume::Receiver<DnsRes>,
    /// Tags with a request queued or running. Dedup: each retry round
    /// re-enters via `setup_outgoing_connection`, and a slow resolver
    /// (the very case this thread exists for) would otherwise let
    /// requests stack unboundedly.
    inflight: HashSet<DnsTag>,
    _join: std::thread::JoinHandle<()>,
}

impl DnsWorker {
    /// Spawn the resolver thread. Panics only if the OS refuses to
    /// create a thread (OOM / `RLIMIT_NPROC`), which is unrecoverable
    /// at daemon setup anyway.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn spawn() -> Self {
        let (req_tx, req_rx) = flume::unbounded::<DnsReq>();
        let (res_tx, res_rx) = flume::unbounded::<DnsRes>();
        let join = std::thread::Builder::new()
            .name("tinc-dns".into())
            .spawn(move || {
                while let Ok(DnsReq { tag, hosts }) = req_rx.recv() {
                    let mut addrs = Vec::new();
                    for (host, port) in hosts {
                        match (host.as_str(), port).to_socket_addrs() {
                            Ok(it) => addrs.extend(it),
                            Err(e) => log::warn!(
                                target: "tincd::conn",
                                "DNS resolve {host}:{port} ({tag:?}): {e}"
                            ),
                        }
                    }
                    if res_tx.send(DnsRes { tag, addrs }).is_err() {
                        return;
                    }
                }
            })
            .expect("dns worker thread spawn");
        Self {
            req_tx,
            res_rx,
            inflight: HashSet::new(),
            _join: join,
        }
    }

    /// Non-blocking enqueue. Dedup'd: a request for a tag that
    /// already has one queued/running is a no-op — the next
    /// [`Self::drain`] will deliver that result and clear the gate.
    /// If the worker thread died the send is silently dropped; the
    /// caller's retry backoff keeps the daemon limping (same
    /// degradation as a dead DHT worker).
    pub fn request(&mut self, tag: DnsTag, hosts: Vec<(String, u16)>) {
        if !self.inflight.insert(tag.clone()) {
            return;
        }
        let _ = self.req_tx.send(DnsReq { tag, hosts });
    }

    /// Non-blocking drain. Clears the inflight gate for each returned
    /// result so the *next* retry round can re-queue.
    pub fn drain(&mut self) -> Vec<DnsRes> {
        let out: Vec<_> = self.res_rx.try_iter().collect();
        for r in &out {
            self.inflight.remove(&r.tag);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn drain_until(w: &mut DnsWorker, want: usize, deadline: Duration) -> Vec<DnsRes> {
        let mut out = Vec::new();
        let end = Instant::now() + deadline;
        while out.len() < want && Instant::now() < end {
            out.extend(w.drain());
            std::thread::sleep(Duration::from_millis(10));
        }
        out
    }

    /// Round-trip through the real worker thread with `localhost` —
    /// every libc has it in `/etc/hosts`, so this exercises the
    /// actual `getaddrinfo` path without touching the network.
    #[test]
    fn worker_roundtrip_localhost() {
        let mut w = DnsWorker::spawn();
        w.request(
            DnsTag::Outgoing("bob".into()),
            vec![("localhost".into(), 655)],
        );
        w.request(DnsTag::Proxy, vec![("localhost".into(), 1080)]);

        let res = drain_until(&mut w, 2, Duration::from_secs(5));
        assert_eq!(res.len(), 2, "missing result(s): {res:?}");
        for r in &res {
            // 127.0.0.1 and/or ::1 — order/count is platform-dependent.
            assert!(r.addrs.iter().any(|a| a.ip().is_loopback()), "{r:?}");
        }
        let out = res
            .iter()
            .find(|r| r.tag == DnsTag::Outgoing("bob".into()))
            .unwrap();
        assert!(out.addrs.iter().all(|a| a.port() == 655));
    }

    /// A second request for the same tag before drain is a no-op;
    /// after drain it's accepted again.
    #[test]
    fn inflight_dedup() {
        let mut w = DnsWorker::spawn();
        let tag = DnsTag::Outgoing("bob".into());
        let hosts = vec![("127.0.0.1".into(), 655)];
        w.request(tag.clone(), hosts.clone());
        w.request(tag.clone(), hosts.clone()); // dedup'd
        let mut res = drain_until(&mut w, 1, Duration::from_secs(5));
        // Give a hypothetical second result a moment to land.
        std::thread::sleep(Duration::from_millis(50));
        res.extend(w.drain());
        assert_eq!(res.len(), 1, "duplicate request should have been dropped");
        // Gate cleared: a fresh request is accepted.
        w.request(tag.clone(), hosts);
        assert!(w.inflight.contains(&tag));
    }
}
