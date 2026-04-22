//! `tinc-dht` worker thread. Owns every blocking `mainline::Dht` call so
//! the epoll thread never parks on the mainline actor's 50 ms recv tick.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use mainline::{Dht, MutableItem};

use super::blind::{blind_public_key, derive};
use super::probe::PROBE_FANOUT;
use super::record::{open_record, parse_record};

/// Requests from the epoll thread into `tinc-dht`.
pub(super) enum WorkerReq {
    /// Refresh cached `info()` + `to_bootstrap()`.
    Snapshot,
    /// Fire-and-forget BEP44 put. (item, seq, plaintext-for-log)
    Publish(MutableItem, i64, String),
    /// Background resolve. (`node_name`, `peer_ed25519_pk`)
    Resolve(String, [u8; 32]),
}

/// Results from `tinc-dht` back to the epoll thread. Drained
/// non-blocking in `tick()`.
pub(super) enum WorkerRes {
    Snapshot {
        vote: Option<Ipv4Addr>,
        firewalled: bool,
        /// `to_bootstrap()` filtered to v4, capped at `PROBE_FANOUT`.
        targets: Vec<SocketAddrV4>,
    },
    /// `ok=false` ⇒ `put_mutable` returned `Err`; seq/value echoed so
    /// `tick()` can log + apply backoff without re-building.
    Published {
        ok: bool,
        seq: i64,
        value: String,
    },
    Resolved(String, Vec<SocketAddr>),
}

/// Background thread that owns **every** call into `mainline::Dht` on the
/// hot path. The mainline actor processes one `ActorMessage` per
/// `rpc.tick()`, and `rpc.tick()` blocks up to 50 ms in `recv_from` — so
/// even `info()` floors at ~50 ms, and `put_mutable` is an iterative
/// `find_node`+store that takes seconds (or times out at ~2 s when the
/// firewall drops replies). Serialising all of that here means the epoll
/// thread never parks on a futex waiting for the actor. The `Dht` handle
/// is a `flume::Sender` clone — same actor the daemon's shutdown-time
/// `routing_nodes()` talks to.
pub(super) struct DhtWorker {
    pub(super) req_tx: flume::Sender<WorkerReq>,
    pub(super) res_rx: flume::Receiver<WorkerRes>,
    /// Names with a `Resolve` inflight or pending in `resolved_buf`.
    /// Dedup: the retry backoff is seconds, the query is sub-second; a
    /// second enqueue before drain is pure waste.
    pub(super) inflight: HashSet<String>,
    /// `Discovery` drop → `req_tx` drops → worker's `recv()` returns
    /// `Disconnected` → thread returns.
    _join: std::thread::JoinHandle<()>,
}

impl DhtWorker {
    pub(super) fn spawn(dht: Dht, secret: Option<[u8; 32]>, period_fn: fn() -> u64) -> Self {
        let (req_tx, req_rx) = flume::unbounded::<WorkerReq>();
        let (res_tx, res_rx) = flume::unbounded::<WorkerRes>();
        let join = std::thread::Builder::new()
            .name("tinc-dht".into())
            .spawn(move || {
                while let Ok(req) = req_rx.recv() {
                    let res = match req {
                        WorkerReq::Snapshot => {
                            let info = dht.info();
                            let targets = dht
                                .to_bootstrap()
                                .into_iter()
                                .filter_map(|s| s.parse().ok())
                                .take(PROBE_FANOUT)
                                .collect();
                            WorkerRes::Snapshot {
                                vote: info.public_address().map(|sa| *sa.ip()),
                                firewalled: info.firewalled(),
                                targets,
                            }
                        }
                        WorkerReq::Publish(item, seq, value) => {
                            // Blocks here — seconds. CAS=None: two
                            // daemons sharing a key just thrash; not
                            // our problem.
                            let ok = dht.put_mutable(item, None).is_ok();
                            WorkerRes::Published { ok, seq, value }
                        }
                        WorkerReq::Resolve(name, key) => {
                            let direct = resolve_plaintext(&dht, &key, secret.as_ref(), period_fn)
                                .map(|v| parse_record(&v).direct)
                                .unwrap_or_default();
                            // Send even on miss: daemon needs to clear
                            // inflight so the *next* retry can re-queue.
                            WorkerRes::Resolved(name, direct)
                        }
                    };
                    if res_tx.send(res).is_err() {
                        return;
                    }
                }
            })
            .expect("tinc-dht thread spawn");
        Self {
            req_tx,
            res_rx,
            inflight: HashSet::new(),
            _join: join,
        }
    }
}

/// One-period fetch + open. Factored so the sync `resolve()`, the
/// background `Resolver` thread, and `tinc-dht-seed --resolve` share the
/// exact same query → verify → decrypt sequence.
///
/// mainline's `get_mutable` iterator yields whatever each responder
/// hands back, in arrival order, with the signature checked against the
/// *responder-supplied* `k` (`rpc.rs` → `from_dht_message`). Two hazards:
///
/// 1. A hostile node on the iterative path can return a self-signed
///    item under its own key. The AEAD layer rejects that (it doesn't
///    know `pk_A` ⇒ wrong `enc_key`), but filtering on `item.key()`
///    keeps the debug log honest and lets us still reach the genuine
///    item later in the stream.
/// 2. A stale or replaying node can return a *genuine* older record
///    (lower seq, decrypts fine) before a fresh one arrives. Draining
///    the iterator and picking `max(seq)` makes us converge to the
///    publisher's most-recent put rather than first-responder's view.
///
/// `Dht::get_mutable_most_recent` exists but compares `seq` with `==`
/// (only breaks ties, never advances), so we hand-roll the reduction.
fn fetch_and_open(
    dht: &Dht,
    peer_pk: &[u8; 32],
    secret: Option<&[u8; 32]>,
    period: u64,
) -> Option<String> {
    let blind_pk = blind_public_key(peer_pk, period)?;
    let d = derive(peer_pk, secret, period);
    let item = dht
        .get_mutable(&blind_pk, Some(&d.salt), None)
        .filter(|i| i.key() == &blind_pk)
        .max_by_key(MutableItem::seq)?;
    let pt = open_record(&d, item.seq(), item.value()).or_else(|| {
        log::debug!(target: "tincd::discovery",
                    "AEAD open failed for period {period} (wrong DhtSecret?)");
        None
    })?;
    String::from_utf8(pt).ok()
}

/// Try `period_fn()` then `period_fn()-1`. Returns the inner plaintext
/// (`"tinc1 …"`) on hit. Used by `tinc-dht-seed --resolve` so the NixOS
/// test can grep `v4=` without re-implementing the crypto.
#[must_use]
pub fn resolve_plaintext(
    dht: &Dht,
    peer_pk: &[u8; 32],
    secret: Option<&[u8; 32]>,
    period_fn: fn() -> u64,
) -> Option<String> {
    let p = period_fn();
    fetch_and_open(dht, peer_pk, secret, p).or_else(|| {
        // p==0 only on a box with epoch-time clock; don't double-query.
        (p > 0)
            .then(|| fetch_and_open(dht, peer_pk, secret, p - 1))
            .flatten()
    })
}
