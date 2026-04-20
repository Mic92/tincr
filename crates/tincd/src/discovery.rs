//! Public-address discovery + DHT publish (Tier 2a).
//!
//! ## What this solves
//!
//! The existing in-band reflexive machinery (`ADD_EDGE`'s `getpeername`
//! address, `ANS_KEY`'s relay-appended observation, `UDP_INFO`) all require
//! a *first* meta-connection to a relay. That relay's `Address=` is the one
//! piece of static config every node still needs. This module supplies a
//! second source: the BitTorrent Mainline DHT.
//!
//! ## How: port-probe + BEP 44 publish
//!
//! Every Mainline DHT response carries an optional `ip` field (BEP 42)
//! echoing the requester's source `(ip, port)` as observed by the responder.
//! We exploit this twice:
//!
//! - **mainline's actor** votes `info().public_address()` across every
//!   response in its iterative queries. Same job as STUN's `XOR-MAPPED-
//!   ADDRESS`, with consensus across millions of nodes. But this learns
//!   the NAT mapping for *mainline's* socket, not tincd's — different fd,
//!   different conntrack entry.
//!
//! - **tincd's port-probe** sends one BEP 5 KRPC `ping` from tincd's
//!   *own* UDP listener to a few DHT nodes. The echo carries the NAT
//!   mapping for the *correct* socket. Re-sent every 25s to keep the
//!   conntrack entry warm — on full-cone NAT, that mapping is open to
//!   *anyone*, so a peer dialling the published address gets through
//!   without a relay.
//!
//! mainline's vote is the higher-frequency signal (every iterative query
//! response, ~seconds). When it changes, the NAT IP changed; we invalidate
//! our cached probe result and re-probe.
//!
//! ## What gets published (BEP 44 mutable items)
//!
//! Two layers, both keyed on things a *mesh member* already has and a
//! *DHT crawler* doesn't (Tor v3 `HSDir` pattern, rend-spec-v3 §2.2.1):
//!
//! ```text
//! period   = floor(unix_time / 86400)
//! h        = SHA3-256(N ‖ pk_A ‖ period_be8)  clamped, mod ℓ
//! blind_pk = h · pk_A           ─ layer 1: ed25519 key blinding
//! (salt, enc_key) = SHAKE256(N ‖ period_be8 ‖ pk_A ‖ DhtSecret?)[..48]
//!
//! k    = blind_pk               (storer verifies sig with this; DLOG to recover pk_A)
//! salt = salt[0..16]
//! v    = b"tincE1" ‖ nonce24 ‖ XChaCha20-Poly1305(enc_key,
//!                                  "tinc1 v4=203.0.113.7:44132 …", aad=seq_be8)
//! ```
//!
//! | Reader                              | sees                      |
//! |-------------------------------------|---------------------------|
//! | DHT storer / crawler                | random key + opaque blob  |
//! | has `hosts/NAME`, mesh sets no secret | derives all, reads addrs |
//! | has `hosts/NAME`, mesh sets `DhtSecret` | wrong salt + key → miss  |
//!
//! Different `h` each day → records unlinkable across periods. Reader
//! near UTC-midnight tries `period` then `period-1` (publisher republishes
//! every 5 min; old record expires from DHT in ~2h). `aad=seq` binds the
//! ciphertext to the BEP 44 seq so a malicious storer can't splice an old
//! ciphertext under a newer seq. Overhead 6+24+16 = 46B; the inner
//! plaintext (`"tinc1 v4=… tcp=… v6=…"`) is ~120B — well under BEP 44's
//! 1000B `v` cap. The inner plaintext stays human-readable (`"tinc1 v4=…"`)
//! so `tinc-dht-seed --resolve` can grep it after decrypt.
//!
//! ## Integration
//!
//! `mainline::Dht` runs on its own `std::thread` (actor over flume channel).
//! `Discovery::spawn()` is called from `Daemon::setup()` and never blocks.
//! `Discovery::tick()` is polled from `on_periodic_tick` (the existing 5s
//! timer); it reads a *cached* snapshot of `info()`/`to_bootstrap()` and
//! decides whether to enqueue a republish. **No mainline call happens on
//! the epoll thread** — every `Dht` round-trip (`info`, `to_bootstrap`,
//! `put_mutable`, `get_mutable`) is owned by the `tinc-dht` thread; the
//! epoll thread only does non-blocking flume `send`/`try_iter`. tincd's
//! epoll loop never sees the DHT socket and never parks on the mainline
//! actor's 50 ms recv tick.
//!
//! The port-probe is the daemon's job, not ours — it owns the UDP socket.
//! `tick()` returns `wants_port_probe`; the daemon sends [`PORT_PROBE_PING`]
//! via its v4 listener and demuxes replies in `handle_incoming_vpn_packet`.
//!
//! ## v6: local enum, not DHT
//!
//! Mainline is a v4 island (`Info::public_address` is `SocketAddrV4`; BEP 32
//! dual-stack was wontfix'd by the `mainline` maintainers). For v6 we ask
//! the kernel: `getifaddrs()`, filter to `2000::/3` global unicast, done.
//! v6 doesn't NAT (RFC 6204 home routers do stateful firewalling, not address
//! translation), so the interface address *is* the reachable address. The
//! firewall still needs the Tier-0 punch — but the address doesn't need
//! discovery.

#![forbid(unsafe_code)]

#[path = "discovery/blind.rs"]
pub mod blind;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use mainline::{Dht, MutableItem};
use rand_core::{OsRng, RngCore};
// Re-export so Daemon::setup() can build a custom-bootstrap Dht for tests
// without taking a direct mainline dep. Also gives us one place to bump
// when mainline's builder API churns.
pub use mainline::DhtBuilder;

use tinc_crypto::sign::SigningKey;

use blind::{BlindSigner, Derived, blind_public_key, current_period, derive};

/// Mainline's hardcoded seed nodes. Vendored: `mainline::rpc` is
/// `pub(crate)` in 6.0.x and the const isn't re-exported. Kept here so
/// `spawn()` can *append* persisted routing-table nodes to the defaults
/// (the builder's `.extra_bootstrap()` on a fresh builder replaces, not
/// augments — it `unwrap_or_default()`s the unset `Option`), and so
/// `tinc-dht-seed --resolve` can dial them without an explicit arg.
pub const DEFAULT_BOOTSTRAP_NODES: [&str; 4] = [
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401",
    "relay.pkarr.org:6881",
];

/// Cap on routing-table addrs written to `dht_nodes`. Transmission's
/// `dht.dat` keeps the full table (~hundreds); 100 is plenty to skip
/// the DNS-seed round-trip on restart and small enough to not care
/// about atomic-rename.
const MAX_PERSISTED_NODES: usize = 100;

/// Re-publish interval. Mainline mutable items expire after ~2h of no
/// republish; iroh uses 5min. We match. The BEP 44 `seq` field (monotonic
/// timestamp) lets DHT nodes drop stale puts cleanly.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(300);

/// Hold the *first* publish until a dialable `v4=`/`tcp=` is known, or
/// this much time has passed since spawn (so a v6-only / no-portmap host
/// still publishes its v6 instead of never). Live on retiolum: eve's
/// first `tick()` ran before the port-probe reply landed, published a
/// v6-only record, set `last_publish`, and the v4 didn't appear in the
/// DHT for another 5 min — a peer bootstrapping purely from DHT waited
/// the full republish interval for a dialable addr.
const FIRST_PUBLISH_GRACE: Duration = Duration::from_secs(30);

/// Port-probe re-send interval. UDP conntrack timeout floors: netfilter
/// default 30s (unreplied) / 180s (assured), consumer routers 30–60s, CGNAT
/// 30s. The seed *did* reply so we're in "assured" on most NATs, but a
/// paranoid box might track per-direction. 25s sits under everything.
const PROBE_KEEPALIVE: Duration = Duration::from_secs(25);

/// How many DHT nodes to probe per round. One honest reply is enough; three
/// covers transient packet loss. The full-cone hole is per-mapping, not
/// per-destination, so probing more nodes doesn't open more holes — it
/// just gets us more chances at the echo.
const PROBE_FANOUT: usize = 3;

/// `v` envelope: 6-byte magic ‖ 24-byte `XChaCha` nonce ‖ ciphertext ‖ 16-byte
/// Poly1305 tag. Magic lets `open_record` reject garbage / future versions
/// before spending an AEAD-open.
const MAGIC: &[u8; 6] = b"tincE1";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Bytes added on top of the inner `"tinc1 …"` plaintext.
pub const AEAD_OVERHEAD: usize = MAGIC.len() + NONCE_LEN + TAG_LEN;

/// BEP 5 KRPC `ping` query, hand-rolled bencode. 58 bytes, fixed.
///
/// `a.id` is 20 zero bytes: `ping` responses don't depend on requester id,
/// and a zero id fails BEP 42's secure-id check so we're omitted from the
/// responder's routing table (intended — we're a freeloader). `t=b"tnc1"`
/// is arbitrary; the daemon demuxes replies on source addr, not tid.
pub const PORT_PROBE_PING: &[u8; 58] = b"d1:ad2:id20:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
      \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
      e1:q4:ping1:t4:tnc11:y1:qe";

/// Parse the BEP 42 `ip` field out of a KRPC response. Substring scan,
/// not full bencode decode: bencode dict keys are sorted, so `ip` is
/// always at offset 1 in conformant replies; the scan tolerates encoders
/// that don't sort. P(false-match in the 20-byte id) ≈ 5×10⁻¹⁴, and the
/// daemon's source-addr gate is the real defence anyway.
///
/// `mainline` unconditionally fills `ip`; libtorrent/transmission have
/// since ~2015. Nodes that omit it → `None` → retry next round.
#[must_use]
pub fn parse_port_probe_reply(pkt: &[u8]) -> Option<SocketAddrV4> {
    const MARKER: &[u8; 6] = b"2:ip6:";
    if pkt.first() != Some(&b'd') {
        return None;
    }
    let idx = pkt.windows(6).position(|w| w == MARKER)?;
    let payload = pkt.get(idx + 6..idx + 12)?;
    // BEP 42 `ip` encoding: 4 octets + 2-byte big-endian port.
    let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let port = u16::from_be_bytes([payload[4], payload[5]]);
    Some(SocketAddrV4::new(ip, port))
}

/// What `Discovery::tick` learned this period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// mainline's BEP 42 vote changed. Wrong port for us (mainline's
    /// socket), but the IP component is shared: a flip means the NAT
    /// moved and our cached `reflexive_v4` is stale.
    PublicV4 { ip: Ipv4Addr, firewalled: bool },
    /// Published a fresh record. `seq` = unix seconds.
    Published { seq: i64, value: String },
}

/// Separate from `DiscoveryEvent`: the probe trigger isn't a log-worthy
/// event, it's a request for the daemon to do I/O on our behalf.
#[derive(Debug, Default)]
pub struct TickResult {
    pub events: Vec<DiscoveryEvent>,
    /// `true` ⇒ daemon should send [`PORT_PROBE_PING`] to each of
    /// [`Discovery::probe_targets`] via its v4 listener, then call
    /// [`Discovery::probe_sent`]. Demux replies with
    /// [`parse_port_probe_reply`] gated on sender ∈ targets.
    pub wants_port_probe: bool,
}

/// State carried across ticks. Lives on `Daemon`.
#[allow(clippy::struct_excessive_bools)] // independent flags, not a state machine
pub struct Discovery {
    dht: Dht,

    /// Last `info().public_address()` IP. Change detection: a flip means
    /// the NAT moved; clears `reflexive_v4` to force re-probe.
    last_vote: Option<Ipv4Addr>,
    /// Logged only — doesn't gate `v4=` (measures mainline's port).
    last_firewalled: bool,

    /// tincd's NAT-mapped `(ip, port)` from the port-probe. What `v4=`
    /// in the published record carries.
    reflexive_v4: Option<SocketAddrV4>,
    /// External `(ip, port)` from a PCP/UPnP-IGD v4 TCP mapping. Unlike
    /// `reflexive_v4` (a NAT-learnt UDP hole), this is a router-installed
    /// DNAT rule — stable for the lease duration, works for *any* peer
    /// without a punch. Feeds `tcp=` in the published record.
    portmapped_tcp: Option<SocketAddr>,
    /// PCP v6 firewall pinhole. No translation — this is our own GUA;
    /// the router just promises to accept inbound to it. Feeds `tcp6=`.
    /// Separate field: a dual-stack node can have both, and dropping
    /// one shouldn't clobber the other in the published record.
    portmapped_tcp6: Option<SocketAddr>,
    /// `set_reflexive_v4` / `set_portmapped_tcp{,6}` changed ⇒ republish now.
    reflexive_dirty: bool,
    /// Gates `wants_port_probe` to one per `PROBE_KEEPALIVE`.
    last_probe: Option<Instant>,

    last_publish: Option<Instant>,
    last_seq: i64,
    /// `with_dht()` time. Gates `FIRST_PUBLISH_GRACE`.
    started: Instant,

    /// We sign BEP 44 records ourselves rather than handing mainline a
    /// `dalek::SigningKey`: tinc's on-disk key is the 64-byte expanded
    /// form (seed gone), dalek wants the seed. `new_signed_unchecked`
    /// takes raw signature bytes.
    key: SigningKey,
    /// `DhtSecret`. Mixed into the SHAKE derive only; the blinding scalar
    /// is `pk_A`-only so a reader with the wrong secret still computes the
    /// right `blind_pk` — the *salt* mismatch is what hides the record.
    secret: Option<[u8; 32]>,
    /// Swappable for the period-rollover test. Prod = `current_period`.
    period_fn: fn() -> u64,
    /// Per-period signer + KDF output. Recomputed when `period_fn()`
    /// disagrees with `epoch.period`.
    epoch: Option<Epoch>,
    /// For `v6=` lines only — v6 doesn't NAT, bind port = reachable port.
    udp_port: u16,

    /// Owns every blocking `mainline::Dht` call. Spawned eagerly in
    /// `with_dht()` — `tick()` needs the cached snapshot from the very
    /// first call.
    worker: DhtWorker,
    /// Last `WorkerRes::Snapshot` from the worker. `tick()` reads these
    /// instead of calling `dht.info()`/`dht.to_bootstrap()` (each of
    /// which is a flume round-trip that floors at ~50 ms while the
    /// mainline actor sits in `recv_from`).
    cached_vote: Option<Ipv4Addr>,
    cached_firewalled: bool,
    cached_targets: Vec<SocketAddrV4>,
    /// `Resolved` results parked here by `tick()`'s drain; consumed by
    /// `drain_resolved()`. The worker's `res_rx` is shared with
    /// Snapshot/Published, so `drain_resolved` can't `try_iter` it.
    resolved_buf: Vec<(String, Vec<SocketAddr>)>,
    /// A `Publish` is queued or running on the worker. Gates `tick()`
    /// from stacking puts (each one is seconds on a bad network).
    publish_inflight: bool,
    /// Retry backoff after a failed `put_mutable`. Starts at 5 s,
    /// doubles to `REPUBLISH_INTERVAL`. Without this a host whose
    /// firewall drops DHT replies retries the ~2 s blocking put every
    /// 5 s tick forever (the bug this worker split exists to fix).
    publish_backoff: Duration,
    last_attempt: Option<Instant>,
}

struct Epoch {
    period: u64,
    signer: BlindSigner,
    derived: Derived,
}

/// Requests from the epoll thread into `tinc-dht`.
enum WorkerReq {
    /// Refresh cached `info()` + `to_bootstrap()`.
    Snapshot,
    /// Fire-and-forget BEP44 put. (item, seq, plaintext-for-log)
    Publish(MutableItem, i64, String),
    /// Background resolve. (`node_name`, `peer_ed25519_pk`)
    Resolve(String, [u8; 32]),
}

/// Results from `tinc-dht` back to the epoll thread. Drained
/// non-blocking in `tick()`.
enum WorkerRes {
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
struct DhtWorker {
    req_tx: flume::Sender<WorkerReq>,
    res_rx: flume::Receiver<WorkerRes>,
    /// Names with a `Resolve` inflight or pending in `resolved_buf`.
    /// Dedup: the retry backoff is seconds, the query is sub-second; a
    /// second enqueue before drain is pure waste.
    inflight: HashSet<String>,
    /// `Discovery` drop → `req_tx` drops → worker's `recv()` returns
    /// `Disconnected` → thread returns.
    _join: std::thread::JoinHandle<()>,
}

impl DhtWorker {
    fn spawn(dht: Dht, secret: Option<[u8; 32]>, period_fn: fn() -> u64) -> Self {
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

impl Discovery {
    /// Spawn the DHT actor. With `bootstrap = None`, dials the real
    /// Mainline DHT via mainline's hardcoded seed nodes
    /// (`router.bittorrent.com:6881` etc — running since ~2008). With
    /// `Some(nodes)`, dials *only* those — the public seeds are NOT mixed
    /// in. Replace, not augment: a local seed mixed with public ones can
    /// outvote them (BEP 42 has no quorum threshold, just plurality).
    ///
    /// `bootstrap` strings are `host:port`; resolution via
    /// `ToSocketAddrs` happens on the actor thread when the first
    /// `find_node` query needs to send. Unparseable entries are skipped
    /// silently by mainline (`to_socket_address` logs a debug line and
    /// continues). An all-garbage list behaves like an isolated node —
    /// `tick()` returns nothing, `publish()` returns `Err(NoClosestNodes)`.
    ///
    /// # Errors
    /// `mainline::DhtBuilder::build()` fails if it can't bind a UDP
    /// socket. Rare (kernel out of ephemeral ports, or a sandbox that
    /// forbids UDP). The caller should log + continue without discovery
    /// — it's a hint source, not load-bearing.
    pub fn spawn(
        key: SigningKey,
        udp_port: u16,
        secret: Option<[u8; 32]>,
        bootstrap: Option<&[String]>,
        extra: &[String],
    ) -> std::io::Result<Self> {
        // Client mode: we put/get, don't help others route. mainline
        // auto-promotes to server if it detects we're not firewalled.
        //
        // `extra` (persisted routing-table nodes from last run) is
        // *appended* in both branches: with `bootstrap=None` it lets a
        // restart skip the DNS-seed round-trip; with an explicit list
        // it can only contain addrs we've previously talked to via that
        // same list, so hermeticity is preserved. `.bootstrap()` is
        // replace-semantics — build the combined Vec ourselves.
        let mut seeds: Vec<String> = match bootstrap {
            None => DEFAULT_BOOTSTRAP_NODES.iter().map(|&s| s.into()).collect(),
            Some(nodes) => nodes.to_vec(),
        };
        seeds.extend_from_slice(extra);
        let dht = Dht::builder().bootstrap(&seeds).build()?;
        Ok(Self::with_dht(dht, key, udp_port, secret))
    }

    /// Spawn against a caller-provided `Dht`. The unit test uses this with a
    /// `mainline::Testnet`-bootstrapped node so the BEP 44 publish/resolve
    /// roundtrip runs entirely on loopback. The production path is `spawn()`.
    ///
    /// Returns immediately; bootstrap happens in the background. First useful
    /// `info()` is ~seconds away (one `find_node` round-trip to seed nodes +
    /// 3-4 hops to find our neighbourhood).
    #[must_use]
    pub fn with_dht(dht: Dht, key: SigningKey, udp_port: u16, secret: Option<[u8; 32]>) -> Self {
        let worker = DhtWorker::spawn(dht.clone(), secret, current_period);
        // Prime: first tick() reads the cache, so kick a snapshot now
        // rather than waiting one full 5 s period for data.
        let _ = worker.req_tx.send(WorkerReq::Snapshot);
        Self {
            dht,
            last_vote: None,
            last_firewalled: true,
            reflexive_v4: None,
            portmapped_tcp: None,
            portmapped_tcp6: None,
            reflexive_dirty: false,
            last_probe: None,
            last_publish: None,
            last_seq: 0,
            started: Instant::now(),
            key,
            secret,
            period_fn: current_period,
            epoch: None,
            udp_port,
            worker,
            cached_vote: None,
            cached_firewalled: true,
            cached_targets: Vec::new(),
            resolved_buf: Vec::new(),
            publish_inflight: false,
            publish_backoff: Duration::from_secs(5),
            last_attempt: None,
        }
    }

    /// Test seam for the period-rollover case: publisher pinned at N,
    /// resolver at N+1 → must hit via the `period-1` fallback.
    #[cfg(test)]
    pub fn set_period_fn(&mut self, f: fn() -> u64) {
        self.period_fn = f;
        self.epoch = None;
    }

    /// Lazily (re)derive the per-period signer + salt + AEAD key. The
    /// republish interval (5 min) is the only caller; rollover is just
    /// "next publish lands under tomorrow's key".
    fn epoch(&mut self) -> &Epoch {
        let p = (self.period_fn)();
        if self.epoch.as_ref().is_none_or(|e| e.period != p) {
            self.epoch = Some(Epoch {
                period: p,
                signer: BlindSigner::new(&self.key, p),
                derived: derive(self.key.public_key(), self.secret.as_ref(), p),
            });
        }
        self.epoch.as_ref().expect("set above")
    }

    /// Snapshot of the actor's routing table as `host:port` strings
    /// (mainline's `to_bootstrap()`; non-stale nodes only). For
    /// [`save_persisted_nodes`] at shutdown — runs once at exit, so the
    /// ~50 ms blocking round-trip into the actor is fine here.
    #[must_use]
    pub fn routing_nodes(&self) -> Vec<String> {
        self.dht.to_bootstrap()
    }

    /// Live nodes from mainline's routing table to port-probe. Better
    /// targets than `dht_bootstrap` (those need DNS, might be down).
    /// `[]` until the worker's first `Snapshot` lands. All v4 —
    /// mainline's routing table is `SocketAddrV4`-only.
    #[must_use]
    pub fn probe_targets(&self) -> Vec<SocketAddrV4> {
        self.cached_targets.clone()
    }

    /// Daemon calls after sending the probe(s). Arms the keepalive timer.
    /// Separate from `probe_targets()` so a daemon that found no v4
    /// listener (and therefore sent nothing) doesn't lie about having
    /// probed.
    pub const fn probe_sent(&mut self, now: Instant) {
        self.last_probe = Some(now);
    }

    /// Daemon calls when [`parse_port_probe_reply`] succeeds on an inbound
    /// packet from a known target. Returns `true` if the address *changed*
    /// (vs `false` for the steady-state keepalive replies that confirm the
    /// mapping is still warm) — daemon logs at info on change, silent on
    /// confirm. Change feeds the republish gate via `reflexive_dirty`.
    pub fn set_reflexive_v4(&mut self, addr: SocketAddrV4) -> bool {
        if self.reflexive_v4 == Some(addr) {
            return false;
        }
        self.reflexive_v4 = Some(addr);
        self.reflexive_dirty = true;
        true
    }

    /// Daemon calls when the portmapper thread reports a v4 TCP
    /// mapping (or `None` on mapping-lost). Feeds `tcp=`. Returns
    /// `true` if changed (⇒ republish on next tick).
    pub fn set_portmapped_tcp(&mut self, addr: Option<SocketAddr>) -> bool {
        if self.portmapped_tcp == addr {
            return false;
        }
        self.portmapped_tcp = addr;
        self.reflexive_dirty = true;
        true
    }

    /// v6 PCP pinhole counterpart. Feeds `tcp6=`.
    pub fn set_portmapped_tcp6(&mut self, addr: Option<SocketAddr>) -> bool {
        if self.portmapped_tcp6 == addr {
            return false;
        }
        self.portmapped_tcp6 = addr;
        self.reflexive_dirty = true;
        true
    }

    /// Queue a background resolve. Non-blocking. Called from
    /// `retry_outgoing` (addr cache exhausted). Dedup'd: a query already
    /// inflight is a no-op.
    pub fn request_resolve(&mut self, node_name: &str, peer_public: [u8; 32]) {
        if self.worker.inflight.contains(node_name) {
            return;
        }
        self.worker.inflight.insert(node_name.to_owned());
        // Unbounded send never blocks. Worker died ⇒ silent drop;
        // tick() will start logging publish failures from the same actor.
        let _ = self
            .worker
            .req_tx
            .send(WorkerReq::Resolve(node_name.to_owned(), peer_public));
    }

    /// Drain resolved records without blocking. Returns `(node_name,
    /// direct_addrs)` pairs the worker completed since last drain.
    /// `direct_addrs` may be empty (DHT had no record — peer offline,
    /// never published, or churn lost it). An empty result still clears
    /// the inflight entry so the next `retry_outgoing` can re-queue.
    ///
    /// Results are moved from the worker channel into `resolved_buf` by
    /// `tick()`; call this *after* `tick()` in the periodic handler.
    pub fn drain_resolved(&mut self) -> Vec<(String, Vec<SocketAddr>)> {
        std::mem::take(&mut self.resolved_buf)
    }

    /// Resolve a peer's published record. Blocking iterative query —
    /// daemon uses [`Self::request_resolve`]/[`Self::drain_resolved`]
    /// instead. This sync path is for tests + `tinc-dht-seed --resolve`.
    ///
    /// `peer_public` is the Ed25519 pubkey from `hosts/NAME` — same bytes
    /// the SPTPS handshake verifies against. mainline rejects bad
    /// signatures (against `blind_pk`) before we see the value; AEAD-open
    /// rejects wrong-secret / spliced-seq after.
    #[must_use]
    pub fn resolve(&self, peer_public: &[u8; 32]) -> Option<ParsedRecord> {
        resolve_plaintext(&self.dht, peer_public, self.secret.as_ref(), self.period_fn)
            .map(|v| parse_record(&v))
    }

    /// Non-blocking poll. Called from `on_periodic_tick` (5s cadence).
    /// Asks the DHT actor for its current vote, decides whether to
    /// republish, and tells the daemon whether to send a port-probe.
    ///
    /// `now` is `timers.now()` — same monotonic clock as the rest of the
    /// daemon, for republish-interval gating.
    #[must_use]
    pub fn tick(&mut self, now: Instant) -> TickResult {
        let mut out = TickResult::default();

        // ── drain worker results (non-blocking). Do this *first* so a
        // publish/snapshot that completed since the previous tick is
        // visible before we gate the next one.
        for res in self.worker.res_rx.try_iter().collect::<Vec<_>>() {
            match res {
                WorkerRes::Snapshot {
                    vote,
                    firewalled,
                    targets,
                } => {
                    self.cached_vote = vote;
                    self.cached_firewalled = firewalled;
                    self.cached_targets = targets;
                }
                WorkerRes::Published { ok, seq, value } => {
                    self.publish_inflight = false;
                    if ok {
                        self.last_publish = Some(now);
                        self.last_seq = seq;
                        self.publish_backoff = Duration::from_secs(5);
                        out.events.push(DiscoveryEvent::Published { seq, value });
                    } else {
                        log::debug!(target: "tincd::discovery",
                                    "DHT publish failed (will retry in {:?})",
                                    self.publish_backoff);
                        self.publish_backoff = (self.publish_backoff * 2).min(REPUBLISH_INTERVAL);
                    }
                }
                WorkerRes::Resolved(name, addrs) => {
                    self.worker.inflight.remove(&name);
                    self.resolved_buf.push((name, addrs));
                }
            }
        }

        // ── ask worker to refresh snapshot for *next* tick.
        let _ = self.worker.req_tx.send(WorkerReq::Snapshot);

        let vote = self.cached_vote;
        let firewalled = self.cached_firewalled;

        // Vote IP changed ⇒ NAT moved ⇒ cached probe is stale. The
        // is_some() gate: Some→None is the actor losing confidence,
        // not the NAT moving — don't invalidate.
        let vote_changed = vote != self.last_vote;
        if vote_changed && vote.is_some() {
            self.reflexive_v4 = None;
        }
        if (vote_changed || firewalled != self.last_firewalled)
            && let Some(ip) = vote
        {
            out.events.push(DiscoveryEvent::PublicV4 { ip, firewalled });
        }
        self.last_vote = vote;
        self.last_firewalled = firewalled;

        // Republish on `reflexive_dirty`, not `vote_changed`: the vote
        // doesn't feed `build_value`, it just invalidated the cache. No
        // point publishing with `v4=` removed; wait for re-probe.
        //
        // First publish (`last_publish == None`) is additionally gated
        // on having a dialable v4/tcp (`ready`): the port-probe and the
        // PCP mapping both arrive seconds after spawn; publishing before
        // them puts a v6-only record in the DHT and then the
        // `REPUBLISH_INTERVAL` gate keeps the v4 out for 5 min.
        // `reflexive_dirty` is set by `set_reflexive_v4` /
        // `set_portmapped_tcp{,6}` and bypasses both gates, so the
        // first useful address triggers an immediate publish anyway.
        // The 30 s grace lets a host that will *never* get v4/tcp
        // (v6-only, no PCP) publish its v6 rather than stay silent.
        let due = self
            .last_publish
            .is_none_or(|last| now.duration_since(last) >= REPUBLISH_INTERVAL);
        let ready = self.last_publish.is_some()
            || self.reflexive_v4.is_some()
            || self.portmapped_tcp.is_some()
            || self.portmapped_tcp6.is_some()
            || now.duration_since(self.started) >= FIRST_PUBLISH_GRACE;
        let backoff_ok = self
            .last_attempt
            .is_none_or(|t| now.duration_since(t) >= self.publish_backoff);
        if !self.publish_inflight
            && backoff_ok
            && (self.reflexive_dirty || (due && ready))
            && let Some((item, seq, value)) = self.build_item()
        {
            self.last_attempt = Some(now);
            self.publish_inflight = true;
            let _ = self
                .worker
                .req_tx
                .send(WorkerReq::Publish(item, seq, value));
        }
        // Clear unconditionally: if a publish is already inflight the
        // fresh address will be picked up by the next `due` window or
        // the next dirty event — don't let the flag pile up.
        self.reflexive_dirty = false;

        // After the invalidation ⇒ vote change triggers immediate re-probe.
        out.wants_port_probe = self.reflexive_v4.is_none()
            || self
                .last_probe
                .is_none_or(|t| now.duration_since(t) >= PROBE_KEEPALIVE);

        out
    }

    /// Build + sign the BEP 44 mutable item. Crypto + `enumerate_v6()`
    /// only — microseconds; the network I/O (`put_mutable`) happens on
    /// `tinc-dht`. `None` if there's nothing worth publishing yet (no
    /// v4, no v6 — we'd just be telling the world our pubkey is online
    /// with no way to reach us).
    fn build_item(&mut self) -> Option<(MutableItem, i64, String)> {
        let value = self.build_value()?;

        // BEP 44 seq: unix seconds, clamped >last_seq for clock skew.
        #[allow(clippy::cast_possible_wrap)] // 2^63 s ≈ 292 Gyr
        let seq = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()) as i64)
            .max(self.last_seq + 1);

        let ep = self.epoch();
        let sealed = seal_record(&ep.derived, seq, value.as_bytes());
        let signable = encode_bep44_signable(seq, &sealed, Some(&ep.derived.salt));
        let signature = ep.signer.sign(&signable);
        let item = MutableItem::new_signed_unchecked(
            ep.signer.public_key(),
            signature,
            &sealed,
            seq,
            Some(&ep.derived.salt),
        );

        Some((item, seq, value))
    }

    /// Test/CLI sync path: build + put inline. Testnet `put_mutable` is
    /// loopback-fast, so blocking here is fine; the daemon never calls
    /// this.
    #[cfg(test)]
    fn publish_sync(&mut self, now: Instant) -> Option<(i64, String)> {
        let (item, seq, value) = self.build_item()?;
        self.dht.put_mutable(item, None).ok()?;
        self.last_publish = Some(now);
        self.last_seq = seq;
        Some((seq, value))
    }

    /// Render the record value. `None` if every field is empty (publishing
    /// "tinc1 " with nothing after it is just a presence beacon; we'd
    /// rather stay quiet).
    fn build_value(&self) -> Option<String> {
        let mut parts: Vec<String> = vec!["tinc1".into()];

        // Unconditional when known: probe reply arriving proves a mapping
        // exists. Full-cone → dialable. Restricted-cone → dial fails but
        // the port is correct, so Tier-0's punch lands first try.
        if let Some(reflexive) = self.reflexive_v4 {
            parts.push(format!("v4={reflexive}"));
        }

        // Router-installed DNAT for our TCP listener. Separate key:
        // `v4=` is the UDP-reflexive port (correct for the SPTPS
        // datagram path / Tier-0 punch); `tcp=` is the meta-conn
        // dial target. They're *different* mappings on the same NAT.
        // v6 mappings (PCP on a v6-only CPE) are rare but legal —
        // SocketAddr's Display already brackets v6.
        if let Some(ext) = self.portmapped_tcp {
            parts.push(format!("tcp={ext}"));
        }
        // v6 pinhole. Distinct key so losing one AF doesn't
        // withdraw the other from the record.
        if let Some(ext) = self.portmapped_tcp6 {
            parts.push(format!("tcp6={ext}"));
        }

        // v6: local-enum, no firewall gate (mainline's `firewalled()` is
        // v4-only). v6 doesn't NAT ⇒ bind port = reachable port. Tier-0
        // deals with the firewall.
        for v6 in enumerate_v6() {
            parts.push(format!("v6=[{v6}]:{}", self.udp_port));
        }

        if parts.len() == 1 {
            // Just "tinc1", no addresses. Nothing useful to say.
            return None;
        }
        Some(parts.join(" "))
    }
}

/// Read the persisted routing-table file (one `ip:port` per line, same
/// shape as the addrcache). Missing / unreadable / unparseable → empty
/// + debug log; the file is a warm-start hint, never load-bearing.
#[must_use]
pub fn load_persisted_nodes(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .map(str::trim)
            // Reject anything that doesn't parse as a v4 sockaddr:
            // mainline's `to_socket_address` would skip it anyway, and
            // this keeps a corrupted file from feeding garbage to DNS.
            .filter(|l| l.parse::<SocketAddrV4>().is_ok())
            .take(MAX_PERSISTED_NODES)
            .map(String::from)
            .collect(),
        Err(e) => {
            log::debug!(target: "tincd::discovery",
                        "dht_nodes load {}: {e} (cold bootstrap)", path.display());
            Vec::new()
        }
    }
}

/// Write up to [`MAX_PERSISTED_NODES`] routing-table addrs, one per
/// line. Best-effort; caller logs on `Err`.
///
/// # Errors
/// Propagates `create_dir_all` / `write` failures (read-only state dir,
/// disk full). The caller treats this as non-fatal.
pub fn save_persisted_nodes(path: &Path, nodes: &[String]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut buf = String::new();
    for n in nodes.iter().take(MAX_PERSISTED_NODES) {
        buf.push_str(n);
        buf.push('\n');
    }
    std::fs::write(path, buf)
}

/// `getifaddrs()` filtered to v6 global unicast (`2000::/3`). Stable
/// `Ipv6Addr::is_unicast_global` is feature-gated; `(s0 & 0xe000) ==
/// 0x2000` is the same predicate. RFC 4941 temp addrs aren't skipped
/// (`IFA_F_TEMPORARY` not surfaced) — they rotate daily, the 5-min
/// republish catches it.
fn enumerate_v6() -> Vec<Ipv6Addr> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    ifaces
        .into_iter()
        .filter_map(|iface| match iface.addr {
            if_addrs::IfAddr::V6(v6) => {
                let ip = v6.ip;
                let s0 = ip.segments()[0];
                ((s0 & 0xe000) == 0x2000).then_some(ip)
            }
            if_addrs::IfAddr::V4(_) => None,
        })
        .collect()
}

/// Seal the inner `"tinc1 …"` plaintext for publish. Random 192-bit
/// nonce per put (`XChaCha` → birthday bound is irrelevant at one put per
/// 5 min). `aad = seq_be8`: the storer can't splice an old ciphertext
/// under a newer seq without the AEAD-open failing.
#[allow(clippy::missing_panics_doc)] // encrypt() only errs on >4GiB input
#[must_use]
pub fn seal_record(d: &Derived, seq: i64, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&d.aead_key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &seq.to_be_bytes(),
            },
        )
        .expect("XChaCha20-Poly1305 encrypt is infallible for <4GiB inputs");
    let mut out = Vec::with_capacity(AEAD_OVERHEAD + plaintext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Reverse of [`seal_record`]. `None` on wrong magic, short input, or
/// AEAD failure (wrong key / wrong seq / tampered). Caller treats all
/// three as "miss".
#[must_use]
pub fn open_record(d: &Derived, seq: i64, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < AEAD_OVERHEAD || &sealed[..MAGIC.len()] != MAGIC {
        return None;
    }
    let nonce = &sealed[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ct = &sealed[MAGIC.len() + NONCE_LEN..];
    XChaCha20Poly1305::new((&d.aead_key).into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ct,
                aad: &seq.to_be_bytes(),
            },
        )
        .ok()
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

/// BEP 44 signable encoding. Vendored — mainline's `encode_signable` is
/// `pub fn` in a non-`pub mod`. NOT a full bencode dict (no `d`/`e`
/// wrapping); just the sorted fragment DHT nodes verify against.
fn encode_bep44_signable(seq: i64, value: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
    let mut signable = Vec::new();
    if let Some(salt) = salt {
        signable.extend(format!("4:salt{}:", salt.len()).into_bytes());
        signable.extend(salt);
    }
    signable.extend(format!("3:seqi{seq}e1:v{}:", value.len()).into_bytes());
    signable.extend(value);
    signable
}

/// Parse a record value. Tolerant: unknown keys + malformed addrs
/// skipped. v6 sorted before v4 in trial order (no NAT, more likely
/// to just work).
#[must_use]
pub fn parse_record(value: &str) -> ParsedRecord {
    let mut out = ParsedRecord::default();
    let mut iter = value.split_ascii_whitespace();

    if iter.next() != Some("tinc1") {
        return out;
    }

    for field in iter {
        let Some((k, v)) = field.split_once('=') else {
            continue;
        };
        // Address-class gate: the record is peer-authored (and, on
        // the unauthenticated DHT path, attacker-authored). Never let
        // loopback / unspecified / multicast / link-local reach the
        // dial queue. RFC1918/ULA pass — see `addr` module docs.
        match k {
            "v4" => {
                if let Ok(sa) = v.parse::<SocketAddr>()
                    && !crate::addr::is_unwanted_dial_addr(&sa)
                {
                    out.direct.push(sa);
                }
            }
            "v6" => {
                // `[addr]:port` — std parser handles the brackets.
                if let Ok(sa) = v.parse::<SocketAddrV6>()
                    && !crate::addr::is_unwanted_dial_target(IpAddr::V6(*sa.ip()))
                {
                    // Prepend: v6 first in trial order.
                    out.direct.insert(0, SocketAddr::V6(sa));
                }
            }
            "tcp" | "tcp6" => {
                if let Ok(sa) = v.parse::<SocketAddr>()
                    && !crate::addr::is_unwanted_dial_addr(&sa)
                {
                    // Either AF is a router-installed accept rule ⇒
                    // best direct-dial candidate. `.tcp` keeps only
                    // the first seen (publish order is tcp, tcp6).
                    if out.tcp.is_none() {
                        out.tcp = Some(sa);
                    }
                    // Also a direct-dial candidate: outgoing meta-
                    // conns are TCP, and a portmapped address is the
                    // *most* likely to accept (no punch needed).
                    // Prepend so it's tried first.
                    out.direct.insert(0, sa);
                }
            }
            _ => {} // unknown key — skip, forward-compat
        }
    }
    out
}

/// Addresses extracted from a peer's published record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    /// Direct-dial candidates (tcp/v6 first, then v4). Feed to
    /// `addr_cache.known` alongside `ADD_EDGE`'s.
    pub direct: Vec<SocketAddr>,
    /// Router-installed TCP DNAT (UPnP/NAT-PMP). Subset of `direct`
    /// surfaced separately so callers that distinguish "dialable
    /// without punch" from "punch hint" can.
    pub tcp: Option<SocketAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D2 regression: peer-authored record must not smuggle
    /// loopback/unspecified/link-local into the dial queue, but
    /// RFC1918 stays (flat-LAN meshes are a supported topology).
    #[test]
    fn parse_record_filters_unwanted_addr_classes() {
        let rec = parse_record(
            "tinc1 tcp=127.0.0.1:22 v4=10.0.0.1:445 v4=0.0.0.0:1 \
             v6=[::1]:80 v6=[fe80::1]:655 v6=[fd00::1]:655",
        );
        let direct: Vec<String> = rec.direct.iter().map(ToString::to_string).collect();
        // Dropped:
        for bad in ["127.0.0.1:22", "0.0.0.0:1", "[::1]:80", "[fe80::1]:655"] {
            assert!(
                !direct.iter().any(|s| s == bad),
                "{bad} leaked into .direct"
            );
        }
        assert!(rec.tcp.is_none(), "loopback tcp= must not populate .tcp");
        // Kept:
        assert!(direct.iter().any(|s| s == "10.0.0.1:445"));
        assert!(direct.iter().any(|s| s == "[fd00::1]:655"));
    }

    /// What `testnet_port_probe_roundtrip` can't reach: out-of-spec
    /// inputs (mainline always sorts, always fills `ip`).
    #[test]
    fn port_probe_reply_parse_edges() {
        // Unsorted keys (`ip` not at offset 1): scan still finds it.
        let unsorted: Vec<u8> =
            [b"d1:y1:r2:ip6:".as_ref(), &[10, 20, 30, 40, 0, 80], b"e"].concat();
        assert_eq!(
            parse_port_probe_reply(&unsorted),
            Some("10.20.30.40:80".parse().unwrap())
        );
        // No `ip` (responder doesn't implement BEP 42): None.
        assert_eq!(
            parse_port_probe_reply(b"d1:rd2:id20:....................e1:y1:re"),
            None
        );
    }

    /// Hand-rolled `PORT_PROBE_PING` → real `serde_bencode` deserializer →
    /// real mainline server → real `serde_bencode` serializer → our
    /// `windows(6)` scanner. No mocks. If either end of the contract
    /// drifts, this catches it.
    #[test]
    fn testnet_port_probe_roundtrip() {
        use mainline::Testnet;
        use std::net::UdpSocket;

        let testnet = Testnet::new(1).expect("testnet");
        let target: SocketAddr = testnet.bootstrap[0].parse().expect("testnet addr");

        // recvfrom timeout: a busted PORT_PROBE_PING gets silently
        // dropped, becomes a test failure not a hang.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        sock.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set_read_timeout");
        let local = match sock.local_addr().expect("local_addr") {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => unreachable!("bound to 127.0.0.1"),
        };

        sock.send_to(PORT_PROBE_PING, target).expect("send_to");

        let mut buf = [0u8; 256];
        let (n, from) = sock.recv_from(&mut buf).expect(
            "no reply from testnet — PORT_PROBE_PING bencode \
             likely rejected by mainline's deserializer",
        );
        assert_eq!(from, target, "reply from wrong source");

        let echoed =
            parse_port_probe_reply(&buf[..n]).expect("reply lacks `ip` field (or scan is wrong)");
        assert_eq!(
            echoed, local,
            "BEP 42 echo mismatch — \
             check sockaddr_to_bytes encoding (port endianness?)"
        );
    }

    /// `seal_record`/`open_record` envelope properties. No DHT.
    #[test]
    fn seal_open_roundtrip() {
        let pk = *SigningKey::from_seed(&[3u8; 32]).public_key();
        let d = derive(&pk, Some(&[0x11; 32]), 5000);
        let plain = b"tinc1 v4=203.0.113.7:44132";
        let sealed = seal_record(&d, 42, plain);

        assert!(sealed.starts_with(MAGIC), "magic prefix");
        assert_eq!(
            sealed.len(),
            AEAD_OVERHEAD + plain.len(),
            "overhead is exactly 46B"
        );
        assert_eq!(open_record(&d, 42, &sealed).as_deref(), Some(&plain[..]));

        // aad=seq binds: storer can't replay old ct under bumped seq.
        assert!(open_record(&d, 43, &sealed).is_none(), "seq+1 → fail");

        // Wrong AEAD key → fail. Covers both "wrong DhtSecret" and
        // "hostile node self-signed forgery" (different pk_A): both
        // reduce to a different `derive()` output, and `open_record`
        // doesn't distinguish.
        let d_wrong = derive(&pk, Some(&[0x22; 32]), 5000);
        assert!(open_record(&d_wrong, 42, &sealed).is_none());

        // Garbage / truncated.
        assert!(open_record(&d, 42, b"tinc1 v4=1.2.3.4:5").is_none());
        assert!(open_record(&d, 42, &sealed[..AEAD_OVERHEAD - 1]).is_none());
    }

    /// Routing table persists across restarts: bootstrap, snapshot,
    /// write, read back, feed as `extra` to a fresh actor. Proves the
    /// `to_bootstrap()` → file → `.bootstrap()` loop closes without
    /// the DNS seeds: the second actor's `bootstrap` is *only* the
    /// loopback Testnet addrs from the file.
    #[test]
    fn testnet_persist_roundtrip() {
        use mainline::Testnet;
        let testnet = Testnet::new(10).expect("testnet");
        let key = SigningKey::from_seed(&[1u8; 32]);
        let pubk = *key.public_key();

        let mut a = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .unwrap(),
            key,
            655,
            None,
        );
        a.set_reflexive_v4("192.0.2.1:1".parse().unwrap());
        // Bootstraps as a side effect (find_node walk fills the table).
        a.publish_sync(Instant::now()).expect("publish");

        let nodes = a.routing_nodes();
        assert!(!nodes.is_empty(), "routing table populated");

        let path =
            std::env::temp_dir().join(format!("tincd-dhtnodes-{:?}", std::thread::current().id()));
        save_persisted_nodes(&path, &nodes).expect("write");
        let loaded = load_persisted_nodes(&path);
        assert_eq!(loaded, nodes, "roundtrip exact");
        // Garbage line filter: only v4-sockaddr-shaped survive.
        std::fs::write(&path, "garbage\n192.0.2.9:1\n[::1]:1\n").unwrap();
        assert_eq!(load_persisted_nodes(&path), vec!["192.0.2.9:1".to_owned()]);
        let _ = std::fs::remove_file(&path);

        // New actor, *only* the persisted addrs as bootstrap (no
        // testnet.bootstrap, no DNS seeds). Resolves ⇒ warm-start works.
        let b = Discovery::with_dht(
            mainline::Dht::builder().bootstrap(&nodes).build().unwrap(),
            SigningKey::from_seed(&[2u8; 32]),
            655,
            None,
        );
        let parsed = b.resolve(&pubk).expect("warm-start resolve");
        assert!(parsed.direct.contains(&"192.0.2.1:1".parse().unwrap()));
    }

    /// First publish gated until a dialable v4/tcp is known. Regression
    /// for the live-eve case: first `tick()` ran with `due=true` before
    /// the port-probe reply / PCP mapping landed, published `tinc1 v6=…`
    /// only, set `last_publish`, and the v4 didn't surface for 5 min.
    #[test]
    fn testnet_first_publish_waits_for_dialable() {
        use mainline::Testnet;
        let testnet = Testnet::new(10).expect("testnet");
        let mut d = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .unwrap(),
            SigningKey::from_seed(&[5u8; 32]),
            655,
            None,
        );

        // Cold tick: no reflexive_v4, no portmap, <30s since spawn ⇒
        // `ready=false` ⇒ NO Published (even if the host has a global
        // v6 and `build_value` would have returned Some).
        let r = d.tick(Instant::now());
        assert!(
            !r.events
                .iter()
                .any(|e| matches!(e, DiscoveryEvent::Published { .. })),
            "first tick must not publish before a dialable addr is known"
        );
        assert!(r.wants_port_probe);
        assert!(d.last_publish.is_none());

        // Portmapper thread reports a TCP DNAT — sets `reflexive_dirty`
        // ⇒ next tick enqueues a publish; the worker completes it and a
        // following tick drains `Published`. Poll until it surfaces.
        assert!(d.set_portmapped_tcp(Some("203.0.113.7:655".parse().unwrap())));
        let mut value = None;
        for _ in 0..50 {
            for e in d.tick(Instant::now()).events {
                if let DiscoveryEvent::Published { value: v, .. } = e {
                    value = Some(v);
                }
            }
            if value.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let value = value.expect("set_portmapped_tcp ⇒ publish via worker");
        assert!(value.contains("tcp=203.0.113.7:655"), "got {value}");
    }

    /// Publish → resolve against a loopback Testnet. The load-bearing
    /// assertion: `BlindSigner::sign` produces bytes that mainline's
    /// stock dalek verifier accepts against `blind_pk` (it can't → DHT
    /// nodes drop the put → resolve returns None), AND the resolver's
    /// `blind_public_key`/`derive` reach the same target/salt/key.
    ///
    /// Doesn't test the port-probe rxpath (lives in the daemon, needs a
    /// socket we don't own); `reflexive_v4` injected directly.
    fn run_publish_resolve(secret: Option<[u8; 32]>) {
        use mainline::Testnet;

        // 10 = mainline's own convergence floor.
        let testnet = Testnet::new(10).expect("testnet spawn");

        let alice_dht = mainline::Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .expect("alice dht");
        let alice_key = SigningKey::from_seed(&[7u8; 32]);
        let alice_pub = *alice_key.public_key();
        let mut alice = Discovery::with_dht(alice_dht, alice_key, 655, secret);

        // Cold start: no reflexive_v4 ⇒ daemon should probe.
        assert!(alice.tick(Instant::now()).wants_port_probe);

        // 44132 ≠ 655: published port must be the reflexive one.
        let reflexive: SocketAddrV4 = "203.0.113.7:44132".parse().unwrap();
        assert!(alice.set_reflexive_v4(reflexive), "first set ⇒ changed");
        assert!(!alice.set_reflexive_v4(reflexive), "same addr ⇒ unchanged");
        // Daemon arms keepalive timer after sendto:
        let now = Instant::now();
        alice.probe_sent(now);
        // (Don't tick(): would consume reflexive_dirty before publish.)
        assert!(alice.reflexive_v4.is_some());
        assert!(now.duration_since(alice.last_probe.unwrap()) < PROBE_KEEPALIVE);

        let (seq, value) = alice
            .publish_sync(Instant::now())
            .expect("publish should succeed against bootstrapped testnet");
        assert!(seq > 0, "seq is unix-seconds, should be nonzero");
        // `value` is the *plaintext* (for the operator's debug log).
        assert!(value.starts_with("tinc1 "));
        assert!(
            value.contains("v4=203.0.113.7:44132"),
            "published port should be the reflexive one, not 655: {value}"
        );

        let bob_dht = mainline::Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .expect("bob dht");
        let bob = Discovery::with_dht(bob_dht, SigningKey::from_seed(&[9u8; 32]), 655, secret);

        // Real ed25519 verification inside mainline's from_dht_message,
        // against the *blinded* key, then AEAD-open with the derived key.
        let parsed = bob
            .resolve(&alice_pub)
            .expect("bob should find alice's record");
        assert!(parsed.direct.contains(&SocketAddr::V4(reflexive)));
        assert_eq!(parsed.tcp, None, "alice didn't set portmapped_tcp");

        // ─── tcp= round-trip: portmapped addr publishes + resolves.
        let mapped: SocketAddr = "203.0.113.7:655".parse().unwrap();
        assert!(alice.set_portmapped_tcp(Some(mapped)));
        assert!(!alice.set_portmapped_tcp(Some(mapped)), "unchanged");
        let (_, value) = alice
            .publish_sync(Instant::now())
            .expect("republish with tcp=");
        assert!(
            value.contains("tcp=203.0.113.7:655"),
            "tcp= missing: {value}"
        );
        // Don't round-trip through the DHT a second time: get_mutable
        // may return the older seq from a node that hasn't converged.
        // Parse the published value directly — the signature path was
        // already proven by the first resolve above.
        let parsed = parse_record(&value);
        assert_eq!(parsed.tcp, Some(mapped));
        assert!(parsed.direct.contains(&mapped));
    }

    #[test]
    fn testnet_publish_resolve_roundtrip_nosecret() {
        run_publish_resolve(None);
    }

    #[test]
    fn testnet_publish_resolve_roundtrip_secret() {
        run_publish_resolve(Some([0x42; 32]));
    }

    /// Period rollover: publisher at N, resolver at N+1 → resolver's
    /// first query (blinded for N+1) misses, fallback to N hits.
    #[test]
    fn testnet_period_rollover_fallback() {
        use mainline::Testnet;
        let testnet = Testnet::new(10).expect("testnet spawn");
        let secret = Some([0x77u8; 32]);

        let alice_key = SigningKey::from_seed(&[7u8; 32]);
        let alice_pub = *alice_key.public_key();
        let mut alice = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .unwrap(),
            alice_key,
            655,
            secret,
        );
        alice.set_period_fn(|| 1000);
        alice.set_reflexive_v4("198.51.100.9:7".parse().unwrap());
        alice.publish_sync(Instant::now()).expect("publish");

        let mut bob = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .unwrap(),
            SigningKey::from_seed(&[9u8; 32]),
            655,
            secret,
        );
        bob.set_period_fn(|| 1001);
        let parsed = bob.resolve(&alice_pub).expect("period-1 fallback");
        assert!(parsed.direct.contains(&"198.51.100.9:7".parse().unwrap()));
    }

    /// The async resolver path: what `retry_outgoing` actually drives.
    /// Same Testnet roundtrip as above, but via `request_resolve` →
    /// background thread → `tick` → `drain_resolved`. Proves:
    /// - dedup (second call before drain is a no-op)
    /// - empty-on-miss (clears inflight, doesn't drop the entry)
    #[test]
    fn testnet_background_resolve_roundtrip() {
        use mainline::Testnet;

        let testnet = Testnet::new(10).expect("testnet spawn");
        let secret = Some([0x55u8; 32]);
        let alice_key = SigningKey::from_seed(&[13u8; 32]);
        let alice_pub = *alice_key.public_key();
        let mut alice = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .expect("alice dht"),
            alice_key,
            655,
            secret,
        );
        alice.set_reflexive_v4("198.51.100.2:9999".parse().unwrap());
        alice.publish_sync(Instant::now()).expect("publish");

        let mut carol = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .expect("carol dht"),
            SigningKey::from_seed(&[17u8; 32]),
            655,
            secret,
        );
        carol.request_resolve("alice", alice_pub);
        assert_eq!(carol.worker.inflight.len(), 1);
        carol.request_resolve("alice", alice_pub);
        assert_eq!(carol.worker.inflight.len(), 1);

        // Also queue a known miss. The worker resolves both serially.
        carol.request_resolve("nobody", [0u8; 32]);
        assert_eq!(carol.worker.inflight.len(), 2);

        // Miss case is slow: iterator yields None only after every
        // inflight request times out (DEFAULT_REQUEST_TIMEOUT = 2s).
        // 8s budget; nextest gives 60. tick() moves Resolved from the
        // worker channel into resolved_buf; drain_resolved() takes it.
        let mut got = std::collections::HashMap::<String, Vec<SocketAddr>>::new();
        for _ in 0..80 {
            let _ = carol.tick(Instant::now());
            for (name, addrs) in carol.drain_resolved() {
                got.insert(name, addrs);
            }
            if got.len() == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(got.len(), 2, "got {got:?} of 2 expected");

        // Inflight cleared by tick()'s drain — next retry can re-queue.
        assert!(carol.worker.inflight.is_empty());

        let alice_addrs = &got["alice"];
        assert!(
            alice_addrs.contains(&"198.51.100.2:9999".parse().unwrap()),
            "alice direct addrs: {alice_addrs:?}"
        );

        // Empty, NOT absent: miss clears inflight so next retry re-queues.
        assert_eq!(got["nobody"], Vec::<SocketAddr>::new());
    }

    #[test]
    fn bep44_signable_matches_mainline() {
        // Spec example from bep_0044.rst.
        let got = encode_bep44_signable(1, b"Hello World!", Some(b"foobar"));
        assert_eq!(got, b"4:salt6:foobar3:seqi1e1:v12:Hello World!");

        // No salt: just seq+v.
        let got = encode_bep44_signable(42, b"x", None);
        assert_eq!(got, b"3:seqi42e1:v1:x");
    }

    #[test]
    fn record_parse() {
        // v6 sorted before v4 (load-bearing: connect.rs trial order).
        let p = parse_record("tinc1 v4=203.0.113.7:44132 v6=[2001:db8::1]:655");
        assert_eq!(
            p.direct,
            vec![
                "[2001:db8::1]:655".parse().unwrap(),
                "203.0.113.7:44132".parse().unwrap(),
            ]
        );
        assert_eq!(p.tcp, None);
        // tcp= present: surfaces in .tcp AND first in .direct,
        // regardless of field order in the record.
        let p = parse_record("tinc1 v4=203.0.113.7:44132 tcp=203.0.113.7:655");
        assert_eq!(p.tcp, Some("203.0.113.7:655".parse().unwrap()));
        assert_eq!(
            p.direct,
            vec![
                "203.0.113.7:655".parse().unwrap(),
                "203.0.113.7:44132".parse().unwrap(),
            ]
        );
        // tcp= first, v6 second: both prepend; trial order is
        // last-prepend-wins. Just checks both land in .direct.
        let p = parse_record("tinc1 tcp=192.0.2.1:655 v6=[2001:db8::1]:655");
        assert_eq!(p.tcp, Some("192.0.2.1:655".parse().unwrap()));
        assert_eq!(p.direct.len(), 2);
        // v6 portmapped (PCP on v6 CPE): brackets parse.
        let p = parse_record("tinc1 tcp=[2001:db8::7]:655");
        assert_eq!(p.tcp, Some("[2001:db8::7]:655".parse().unwrap()));
        // tcp + tcp6 both present: both land in .direct; .tcp keeps
        // the v4 (publish order). tcp6 prepended after ⇒ first.
        let p = parse_record("tinc1 tcp=192.0.2.1:655 tcp6=[2001:db8::7]:655");
        assert_eq!(p.tcp, Some("192.0.2.1:655".parse().unwrap()));
        assert_eq!(
            p.direct,
            vec![
                "[2001:db8::7]:655".parse().unwrap(),
                "192.0.2.1:655".parse().unwrap(),
            ]
        );
        // Unknown keys + malformed values: skip, don't fail.
        let p = parse_record("tinc1 v4=garbage tcp=nope future=thing v6=[fd00::1]:655 ext=x:1");
        assert_eq!(p.direct, vec!["[fd00::1]:655".parse().unwrap()]);
        assert_eq!(p.tcp, None);
        // Wrong version.
        assert_eq!(parse_record("tinc2 v4=1.2.3.4:5"), ParsedRecord::default());
        assert_eq!(parse_record(""), ParsedRecord::default());
    }
}
