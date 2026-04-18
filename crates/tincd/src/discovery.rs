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
//! ```text
//! key   = node's Ed25519 pubkey (the same key in hosts/NAME)
//! salt  = b"tinc"  (so other apps publishing under the same key don't collide)
//! value = "tinc1 v4=203.0.113.7:44132 v6=[2001:db8::1]:655"
//!         ^^^^^ format version
//!               ^^^ port-probe result: tincd's NAT-mapped (ip, port). Both correct.
//!                                        ^^^ local-enum global-unicast v6 (no NAT ⇒ correct)
//! ```
//!
//! `v4=` is published unconditionally when known: the probe reply arriving
//! proves the NAT created a mapping. On full-cone NAT, peers can dial it.
//! On restricted-cone they can't (only the seed's IP is allowed) — but the
//! port number is *correct*, so when Tier-0 coordinates a simultaneous send
//! the punch lands first try instead of guessing.
//!
//! The value is plain text, not pkarr's DNS-packet encoding. We don't *need*
//! a DNS frontend (no resolver between us and the DHT), and a hand-parseable
//! format means `bep44-get <pubkey>` debugging works without a DNS decoder.
//! The `mainline::MutableItem` signing is BEP 44 standard either way.
//!
//! ## Integration
//!
//! `mainline::Dht` runs on its own `std::thread` (actor over flume channel).
//! `Discovery::spawn()` is called from `Daemon::setup()` and never blocks.
//! `Discovery::tick()` is polled from `on_periodic_tick` (the existing 5s
//! timer); it does one non-blocking `info()` query and decides whether to
//! republish. tincd's epoll loop never sees the DHT socket.
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

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use mainline::{Dht, MutableItem};
// Re-export so Daemon::setup() can build a custom-bootstrap Dht for tests
// without taking a direct mainline dep. Also gives us one place to bump
// when mainline's builder API churns.
pub use mainline::DhtBuilder;

use tinc_crypto::sign::SigningKey;

/// Re-publish interval. Mainline mutable items expire after ~2h of no
/// republish; iroh uses 5min. We match. The BEP 44 `seq` field (monotonic
/// timestamp) lets DHT nodes drop stale puts cleanly.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(300);

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

/// BEP 44 salt. Segregates our records from anything else published under
/// the same Ed25519 key (pkarr uses no salt → root namespace; we use
/// `b"tinc"` so a node that's *also* an iroh node doesn't get its records
/// stomped).
const SALT: &[u8] = b"tinc";

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

    /// We sign BEP 44 records ourselves rather than handing mainline a
    /// `dalek::SigningKey`: tinc's on-disk key is the 64-byte expanded
    /// form (seed gone), dalek wants the seed. `new_signed_unchecked`
    /// takes raw signature bytes.
    key: SigningKey,
    /// For `v6=` lines only — v6 doesn't NAT, bind port = reachable port.
    udp_port: u16,

    /// Lazy: `None` until first `request_resolve`.
    resolver: Option<Resolver>,
}

/// Background `get_mutable` thread. Resolves fire on the retry-outgoing
/// schedule (5s/10s/15s backoff); a daemon with several stalled `ConnectTo`
/// peers could stack multiple blocking queries per tick. The thread
/// serializes them off the epoll loop. The Dht handle is a `flume::Sender`
/// clone — same actor `tick()` queues against.
struct Resolver {
    req_tx: flume::Sender<(String, [u8; 32])>,
    res_rx: flume::Receiver<(String, Vec<SocketAddr>)>,
    /// Names with a query inflight or pending in `res_rx`. Dedup: the
    /// retry backoff is seconds, the query is sub-second; a second
    /// enqueue before drain is pure waste.
    inflight: HashSet<String>,
    /// `Discovery` drop → `req_tx` drops → worker's `recv()` returns
    /// `Disconnected` → thread returns.
    _join: std::thread::JoinHandle<()>,
}

impl Resolver {
    fn spawn(dht: Dht) -> Self {
        let (req_tx, req_rx) = flume::unbounded::<(String, [u8; 32])>();
        let (res_tx, res_rx) = flume::unbounded::<(String, Vec<SocketAddr>)>();
        let join = std::thread::Builder::new()
            .name("dht-resolve".into())
            .spawn(move || {
                while let Ok((name, key)) = req_rx.recv() {
                    let direct = dht
                        .get_mutable(&key, Some(SALT), None)
                        .next()
                        .and_then(|item| {
                            std::str::from_utf8(item.value())
                                .ok()
                                .map(|v| parse_record(v).direct)
                        })
                        .unwrap_or_default();
                    // Send even on miss: daemon needs to clear inflight
                    // so the *next* retry can re-queue.
                    if res_tx.send((name, direct)).is_err() {
                        return;
                    }
                }
            })
            .expect("dht-resolve thread spawn");
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
        bootstrap: Option<&[String]>,
    ) -> std::io::Result<Self> {
        // Client mode: we put/get, don't help others route. mainline
        // auto-promotes to server if it detects we're not firewalled.
        let dht = match bootstrap {
            None => Dht::client()?,
            // .bootstrap() replaces, not appends — the semantics we want.
            Some(nodes) => Dht::builder().bootstrap(nodes).build()?,
        };
        Ok(Self::with_dht(dht, key, udp_port))
    }

    /// Spawn against a caller-provided `Dht`. The unit test uses this with a
    /// `mainline::Testnet`-bootstrapped node so the BEP 44 publish/resolve
    /// roundtrip runs entirely on loopback. The production path is `spawn()`.
    ///
    /// Returns immediately; bootstrap happens in the background. First useful
    /// `info()` is ~seconds away (one `find_node` round-trip to seed nodes +
    /// 3-4 hops to find our neighbourhood).
    #[must_use]
    pub const fn with_dht(dht: Dht, key: SigningKey, udp_port: u16) -> Self {
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
            key,
            udp_port,
            resolver: None,
        }
    }

    /// Live nodes from mainline's routing table to port-probe. Better
    /// targets than `dht_bootstrap` (those need DNS, might be down).
    /// `[]` until bootstrapped. All v4 — mainline's routing table is
    /// `SocketAddrV4`-only.
    #[must_use]
    pub fn probe_targets(&self) -> Vec<SocketAddrV4> {
        self.dht
            .to_bootstrap()
            .into_iter()
            .filter_map(|s| s.parse().ok())
            .take(PROBE_FANOUT)
            .collect()
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
    /// inflight is a no-op. Lazy thread spawn on first call.
    pub fn request_resolve(&mut self, node_name: &str, peer_public: [u8; 32]) {
        let resolver = self
            .resolver
            .get_or_insert_with(|| Resolver::spawn(self.dht.clone()));
        if resolver.inflight.contains(node_name) {
            return;
        }
        resolver.inflight.insert(node_name.to_owned());
        // Unbounded send never blocks. Worker died ⇒ silent drop;
        // tick() will start logging publish failures from the same actor.
        let _ = resolver.req_tx.send((node_name.to_owned(), peer_public));
    }

    /// Drain resolved records without blocking. Returns `(node_name,
    /// direct_addrs)` pairs the worker completed since last drain.
    /// `direct_addrs` may be empty (DHT had no record — peer offline,
    /// never published, or churn lost it). An empty result still clears
    /// the inflight entry so the next `retry_outgoing` can re-queue.
    pub fn drain_resolved(&mut self) -> Vec<(String, Vec<SocketAddr>)> {
        let Some(resolver) = &mut self.resolver else {
            return Vec::new();
        };
        resolver
            .res_rx
            .try_iter()
            .inspect(|(name, _)| {
                resolver.inflight.remove(name);
            })
            .collect()
    }

    /// Resolve a peer's published record. Blocking iterative query —
    /// daemon uses [`Self::request_resolve`]/[`Self::drain_resolved`]
    /// instead. This sync path is for tests + `tinc-dht-seed --resolve`.
    ///
    /// `peer_public` is the Ed25519 pubkey from `hosts/NAME` — same bytes
    /// the SPTPS handshake verifies against. mainline rejects bad
    /// signatures before we see the value.
    #[must_use]
    pub fn resolve(&self, peer_public: &[u8; 32]) -> Option<ParsedRecord> {
        let item = self.dht.get_mutable(peer_public, Some(SALT), None).next()?;
        let value = std::str::from_utf8(item.value()).ok()?;
        Some(parse_record(value))
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

        // info() is a flume round-trip, no network I/O. Microseconds.
        let info = self.dht.info();
        let vote = info.public_address().map(|sa| *sa.ip());
        let firewalled = info.firewalled();

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
        let due = self
            .last_publish
            .is_none_or(|last| now.duration_since(last) >= REPUBLISH_INTERVAL);
        if (self.reflexive_dirty || due)
            && let Some((seq, value)) = self.publish(now)
        {
            out.events.push(DiscoveryEvent::Published { seq, value });
        }
        self.reflexive_dirty = false;

        // After the invalidation ⇒ vote change triggers immediate re-probe.
        out.wants_port_probe = self.reflexive_v4.is_none()
            || self
                .last_probe
                .is_none_or(|t| now.duration_since(t) >= PROBE_KEEPALIVE);

        out
    }

    /// Build the record value, sign it, put to the DHT. Returns the (seq,
    /// value) pair on success for logging; `None` if there's nothing worth
    /// publishing yet (no v4, no v6 — we'd just be telling the world our
    /// pubkey is online with no way to reach us).
    fn publish(&mut self, now: Instant) -> Option<(i64, String)> {
        let value = self.build_value()?;

        // BEP 44 seq: unix seconds, clamped >last_seq for clock skew.
        #[allow(clippy::cast_possible_wrap)] // 2^63 s ≈ 292 Gyr
        let seq = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()) as i64)
            .max(self.last_seq + 1);

        let signable = encode_bep44_signable(seq, value.as_bytes(), Some(SALT));
        let signature = self.key.sign(&signable);
        let public = *self.key.public_key();

        let item =
            MutableItem::new_signed_unchecked(public, signature, value.as_bytes(), seq, Some(SALT));

        // Blocking, ~hundreds of ms once bootstrapped. We're on the 5s
        // periodic timer (same precedent as the contradicting-edge sleep).
        // CAS=None: two daemons sharing a key just thrash; not our problem.
        match self.dht.put_mutable(item, None) {
            Ok(_id) => {
                self.last_publish = Some(now);
                self.last_seq = seq;
                Some((seq, value))
            }
            Err(e) => {
                // Don't bump last_publish — interval gate stays open.
                log::debug!(target: "tincd::discovery",
                            "DHT publish failed (will retry): {e:?}");
                None
            }
        }
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
        match k {
            "v4" => {
                if let Ok(sa) = v.parse::<SocketAddr>() {
                    out.direct.push(sa);
                }
            }
            "v6" => {
                // `[addr]:port` — std parser handles the brackets.
                if let Ok(sa) = v.parse::<SocketAddrV6>() {
                    // Prepend: v6 first in trial order.
                    out.direct.insert(0, SocketAddr::V6(sa));
                }
            }
            "tcp" | "tcp6" => {
                if let Ok(sa) = v.parse::<SocketAddr>() {
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

    /// Publish → resolve against a loopback Testnet. The load-bearing
    /// assertion: tinc's expanded-key `SigningKey::sign` produces bytes
    /// that mainline's dalek verifier accepts (it can't — wrong sig
    /// encoding → DHT nodes drop the put → resolve returns None).
    ///
    /// Doesn't test the port-probe rxpath (lives in the daemon, needs a
    /// socket we don't own); `reflexive_v4` injected directly.
    #[test]
    fn testnet_publish_resolve_roundtrip() {
        use mainline::Testnet;

        // 10 = mainline's own convergence floor.
        let testnet = Testnet::new(10).expect("testnet spawn");

        let alice_dht = mainline::Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .expect("alice dht");
        let alice_key = SigningKey::from_seed(&[7u8; 32]);
        let alice_pub = *alice_key.public_key();
        let mut alice = Discovery::with_dht(alice_dht, alice_key, 655);

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
            .publish(Instant::now())
            .expect("publish should succeed against bootstrapped testnet");
        assert!(seq > 0, "seq is unix-seconds, should be nonzero");
        assert!(value.starts_with("tinc1 "));
        assert!(
            value.contains("v4=203.0.113.7:44132"),
            "published port should be the reflexive one, not 655: {value}"
        );

        let bob_dht = mainline::Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .expect("bob dht");
        let bob = Discovery::with_dht(bob_dht, SigningKey::from_seed(&[9u8; 32]), 655);

        // Real ed25519 verification inside mainline's from_dht_message.
        let parsed = bob
            .resolve(&alice_pub)
            .expect("bob should find alice's record");
        assert!(parsed.direct.contains(&SocketAddr::V4(reflexive)));
        assert_eq!(parsed.tcp, None, "alice didn't set portmapped_tcp");

        // ─── tcp= round-trip: portmapped addr publishes + resolves.
        let mapped: SocketAddr = "203.0.113.7:655".parse().unwrap();
        assert!(alice.set_portmapped_tcp(Some(mapped)));
        assert!(!alice.set_portmapped_tcp(Some(mapped)), "unchanged");
        let (_, value) = alice.publish(Instant::now()).expect("republish with tcp=");
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

        // Negative: unknown pubkey returns None (no garbage, no panic).
        assert!(bob.resolve(&[0u8; 32]).is_none());
    }

    /// The async resolver path: what `retry_outgoing` actually drives.
    /// Same Testnet roundtrip as above, but via `request_resolve` →
    /// background thread → `drain_resolved`. Proves:
    /// - lazy spawn (first call creates the thread)
    /// - dedup (second call before drain is a no-op)
    /// - empty-on-miss (clears inflight, doesn't drop the entry)
    #[test]
    fn testnet_background_resolve_roundtrip() {
        use mainline::Testnet;

        let testnet = Testnet::new(10).expect("testnet spawn");
        let alice_key = SigningKey::from_seed(&[13u8; 32]);
        let alice_pub = *alice_key.public_key();
        let mut alice = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .expect("alice dht"),
            alice_key,
            655,
        );
        alice.set_reflexive_v4("198.51.100.2:9999".parse().unwrap());
        alice.publish(Instant::now()).expect("publish");

        let mut carol = Discovery::with_dht(
            mainline::Dht::builder()
                .bootstrap(&testnet.bootstrap)
                .build()
                .expect("carol dht"),
            SigningKey::from_seed(&[17u8; 32]),
            655,
        );
        // Lazy spawn: resolver doesn't exist until first request.
        assert!(carol.resolver.is_none());

        carol.request_resolve("alice", alice_pub);
        assert!(carol.resolver.is_some());
        assert_eq!(carol.resolver.as_ref().unwrap().inflight.len(), 1);
        carol.request_resolve("alice", alice_pub);
        assert_eq!(carol.resolver.as_ref().unwrap().inflight.len(), 1);

        // Also queue a known miss. The worker resolves both serially.
        carol.request_resolve("nobody", [0u8; 32]);
        assert_eq!(carol.resolver.as_ref().unwrap().inflight.len(), 2);

        // Miss case is slow: iterator yields None only after every
        // inflight request times out (DEFAULT_REQUEST_TIMEOUT = 2s).
        // 8s budget; nextest gives 60.
        let mut got = std::collections::HashMap::<String, Vec<SocketAddr>>::new();
        for _ in 0..80 {
            for (name, addrs) in carol.drain_resolved() {
                got.insert(name, addrs);
            }
            if got.len() == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(got.len(), 2, "got {got:?} of 2 expected");

        // Inflight cleared by drain — next retry can re-queue.
        assert!(carol.resolver.as_ref().unwrap().inflight.is_empty());

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
        let p = parse_record("tinc1 v4=garbage tcp=nope future=thing v6=[::1]:655 ext=x:1");
        assert_eq!(p.direct, vec!["[::1]:655".parse().unwrap()]);
        assert_eq!(p.tcp, None);
        // Wrong version.
        assert_eq!(parse_record("tinc2 v4=1.2.3.4:5"), ParsedRecord::default());
        assert_eq!(parse_record(""), ParsedRecord::default());
    }
}
