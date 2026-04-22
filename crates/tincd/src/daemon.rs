//! `Daemon` — all the C-global state as one struct, plus the main loop.
//!
//! Loop shape: tick → turn → match. `IoWhat` is the `W` in
//! `EventLoop<W>`. `run()` consumes `self`; teardown is `Drop`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::inthash::IntHashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use slotmap::SlotMap;
use tinc_crypto::sign::SigningKey;
use tinc_device::Device;
use tinc_event::{EventLoop, Ready, SelfPipe, TimerId, Timers};
use tinc_graph::{EdgeId, Graph, NodeId, Route};
use tinc_proto::AddrStr;

use crate::conn::Connection;
use crate::control::ControlSocket;
use crate::egress::UdpEgress;
use crate::listen::{Listener, Tarpit};
use crate::node_id::NodeId6Table;
use crate::outgoing::{Outgoing, OutgoingId};
use crate::seen::SeenRequests;
use crate::subnet_tree::SubnetTree;
use crate::{icmp, mac_lease, route_mac};

mod connect;
mod dp;
mod gossip;
mod metaconn;
mod net;
mod periodic;
mod purge;
mod settings;
mod setup;
mod txpath;

// Re-exports so the 7 submodules' `use super::*;` keep resolving
// items that moved into settings.rs. `lib.rs` re-exports
// `DaemonSettings` from this module's root.
pub(crate) use dp::DataPlane;
pub use settings::{DaemonSettings, ForwardingMode, RoutingMode, read_dht_secret_file};

// `UPnP` config knob. With the feature off the type still exists
// (settings.rs stores it unconditionally) but only `No` is reachable
// — `load_settings` warns and ignores the config line, C parity with
// the `--disable-miniupnpc` build.
#[cfg(feature = "upnp")]
pub use crate::portmap::UpnpMode;
#[cfg(not(feature = "upnp"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpnpMode {
    #[default]
    No,
}
#[cfg(not(feature = "upnp"))]
impl UpnpMode {
    // Signature matches the feature-on variant so settings.rs is
    // cfg-free; clippy's unnecessary-wraps doesn't see across cfgs.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn from_config(_: &str) -> Option<Self> {
        log::warn!(target: "tincd",
            "UPnP was requested, but tincd was built without the `upnp` feature");
        Some(Self::No)
    }
}
pub(crate) use settings::{
    apply_reloadable_settings, parse_connect_to_from_config, parse_subnets_from_config,
};

// SPTPS record-type bits for the per-tunnel data channel.
// Type 0 = plain IP packet (router mode, no compression). Bits OR.
pub(crate) const PKT_NORMAL: u8 = 0;
const PKT_COMPRESSED: u8 = 1;
const PKT_MAC: u8 = 2;
const PKT_PROBE: u8 = 4;

// dispatch enums - the W in EventLoop<W> / Timers<W> / SelfPipe<W>

pub use crate::ids::ConnId;

/// Per-peer runtime annotation. Split from graph topology so
/// `tinc-graph` stays `#![no_std]`-clean.
#[derive(Debug, Clone)]
pub struct NodeState {
    /// Our edge to this peer. `terminate_connection` deletes +
    /// broadcasts `DEL_EDGE`.
    pub edge: Option<EdgeId>,
    /// Direct connection. None = known but not directly connected.
    pub conn: Option<ConnId>,
    /// TCP addr, port rewritten to UDP.
    pub edge_addr: Option<SocketAddr>,
    /// Avg of RTTs, ms.
    pub edge_weight: i32,
    /// Top byte = peer's `PROT_MINOR`.
    pub edge_options: crate::proto::ConnOptions,
}

/// Six variants = six io callbacks the event loop dispatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoWhat {
    /// Self-pipe read end.
    Signal,
    /// Control socket listener.
    UnixListener,
    /// TUN/TAP fd. `Dummy.fd()` → None → never registered.
    Device,
    /// Meta connection.
    Conn(ConnId),
    /// TCP listener. u8: MAXSOCKETS=16.
    Tcp(u8),
    /// UDP listener.
    Udp(u8),
}

/// Timer dispatch tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerWhat {
    /// +1s. Connection liveness sweep.
    Ping,
    /// +5s. Autoconnect + contradicting-edge backoff.
    Periodic,
    /// +`keylifetime`s (default 3600). Forces SPTPS rekey on every
    /// active tunnel.
    KeyExpire,
    /// +10s. Gossip dedup-cache eviction.
    AgePastRequests,
    /// +10s. Lazy-armed on first `learn_mac` (when `MacLeases::learn`
    /// returns true = empty).
    AgeSubnets,
    /// Per-outgoing retry backoff.
    RetryOutgoing(OutgoingId),
    /// `sd_notify(WATCHDOG=1)` keepalive at half of `WatchdogSec`.
    /// Armed iff `WATCHDOG_USEC` was in the env at startup. Driven
    /// from the event loop (NOT a side thread) so a wedged loop
    /// stops pinging and systemd actually restarts us.
    Watchdog,
}

/// TERM/QUIT/INT all map to Exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalWhat {
    /// SIGHUP.
    Reload,
    /// SIGTERM/INT/QUIT. Carries the raw signum so the exit log
    /// can say which one (post-mortem: `^C` vs `systemctl stop`
    /// vs `kill -QUIT`).
    Exit(i32),
    /// SIGALRM.
    Retry,
}

/// What `run()` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// Loop returned cleanly (`running` set false by a handler).
    Clean,
    /// Poll returned an error.
    PollError,
}

/// Daemon-side wrapper around `Listener`. Bundles the last
/// `IP_TOS`/`IPV6_TCLASS` set on the UDP socket (only `setsockopt`
/// when changed) and the egress sender. Kept here, not on
/// `Listener`, so `listen.rs` stays event-loop-agnostic.
pub(crate) struct ListenerSlot {
    pub(crate) listener: Listener,
    pub(crate) last_tos: u8,
    /// `UdpEgress` for this listener's UDP socket. `linux::Fast`
    /// (`UDP_SEGMENT` cmsg, one sendmsg per batch) on Linux;
    /// `Portable` (count × sendto, same wire output) elsewhere.
    /// `Box<dyn>`: vtable indirect per-BATCH (~20k/s @ 10G × 2ns
    /// ≈ nothing). Lives here, not in a parallel `Vec`, because
    /// the `sock` index already picks the slot - one fewer
    /// coherence invariant to maintain.
    pub(crate) egress: Box<dyn UdpEgress>,
}

/// The daemon. Everything that was a global is a field; `run()` is
/// the main loop.
///
/// Why fields are `pub(crate)` not `pub`: the loop body matches on
/// `IoWhat` and reaches into ALL the fields. There's no encapsulation
/// to defend - the loop IS the daemon. The Rust gain is `&mut self`
/// exclusivity: the compiler knows no two handlers run concurrently.
#[allow(clippy::struct_excessive_bools)] // independent gates
// (overwrite_mac, any_pcap, etc), not a state enum.
pub struct Daemon {
    // ─── arena
    /// Slotmap not `Vec<Option>` - generational keys. A `ConnId`
    /// from a closed connection is a different key than the next
    /// connection allocated in the same slot.
    pub(crate) conns: SlotMap<ConnId, Connection>,

    /// Per-connection event-loop handle. Parallel map because
    /// `Connection` doesn't know about `tinc-event` (layering).
    ///
    /// (Could be a field on `Connection`. Argument for parallel map:
    /// `Connection` is testable without `EventLoop`. Argument against:
    /// two-map coherence. For now: two maps, debug asserts on
    /// coherence. Revisit if it bites.)
    pub(crate) conn_io: slotmap::SecondaryMap<ConnId, tinc_event::IoId>,

    // ─── substrate
    /// The TUN/TAP. `Box<dyn>` - the variant (`Dummy`/`Tun`/`Fd`/
    /// `Raw`/`Bsd`) is chosen at setup time by `DeviceType`.
    pub(crate) device: Box<dyn Device>,

    /// The control listener.
    pub(crate) control: ControlSocket,

    /// TCP+UDP pairs. `IoWhat::Tcp(i)` indexes here. `Vec` not
    /// array because `Listener` doesn't impl `Default` (sockets
    /// aren't defaultable).
    pub(crate) listeners: Vec<ListenerSlot>,

    /// Tarpit ring buffer + leaky-bucket state. Mutated on every
    /// TCP accept.
    pub(crate) tarpit: Tarpit,

    /// 64 hex chars. Compared in `handle_id`.
    pub(crate) cookie: String,

    /// Kept so `Drop` can unlink.
    pub(crate) pidfile: PathBuf,

    /// Our node name from `tinc.conf:Name`. Appears in the
    /// `send_id` greeting and in dump output.
    pub(crate) name: String,

    /// Our Ed25519 private key. Loaded once at startup from
    /// `confbase/ed25519_key.priv` (or `Ed25519PrivateKeyFile`).
    /// Used for SPTPS auth: every peer handshake clones this via
    /// `to_blob`/`from_blob` (`SigningKey` deliberately isn't
    /// `Clone` - the roundtrip makes copies visible). Never
    /// reloaded (a key change is a daemon restart, not a SIGHUP).
    pub(crate) mykey: SigningKey,

    /// Kept so `id_h` peer-branch can resolve `hosts/NAME` paths.
    /// Stored once here, borrowed into each `IdCtx`.
    pub(crate) confbase: PathBuf,

    /// Our options bitfield (`PROT_MINOR` in top byte). Built from
    /// global `IndirectData`/`TCPOnly`/`PMTUDiscovery`/`ClampMSS` at
    /// `setup()`.
    pub(crate) myself_options: crate::proto::ConnOptions,

    /// Read back from `listeners[0].udp_port()` after bind.
    /// `bind_reusing_port` makes UDP follow TCP's ephemeral with
    /// `Port = 0`, so this equals `listeners[0].local.port()`.
    pub(crate) my_udp_port: u16,

    /// Topology half: nodes + directed edges. What `sssp`/`mst`
    /// walk. Split from runtime annotation - see `NodeState` doc.
    ///
    /// `myself` is added at setup. Transitively-known nodes are
    /// added by `lookup_or_add_node` from `ADD_EDGE/ADD_SUBNET`
    /// handlers. The graph crate has no name→id reverse lookup -
    /// that's `node_ids` below.
    pub(crate) graph: Graph,

    /// name → `NodeId`. The reverse lookup `tinc-graph` doesn't
    /// have. Populated alongside `graph.add_node()` in
    /// `lookup_or_add_node`.
    ///
    /// Invariant: every entry's `NodeId` is a live slot in `graph`.
    /// Nodes are never deleted (only on `purge`); when del lands,
    /// it removes from here too.
    pub(crate) node_ids: HashMap<String, NodeId>,

    /// Our own `NodeId` in `graph`. The `from == myself` checks in
    /// the edge/subnet handlers compare against this.
    pub(crate) myself: NodeId,

    /// The routing table. `ADD_SUBNET` inserts, `DEL_SUBNET` removes,
    /// `route_ipv4` reads, `dump subnets` walks.
    pub(crate) subnets: SubnetTree,

    /// DNS stub config. `None` = feature off (the TUN-intercept
    /// branch in `route_packet` never fires). Non-reloadable: the
    /// magic IP has to be added to the TUN in `tinc-up`, and
    /// re-running that mid-daemon is the same can-of-worms as
    /// `DeviceType` reload.
    pub(crate) dns: Option<crate::dns::DnsConfig>,

    /// Anti-loop dedup for flooded ADD/DEL messages. Handlers call `seen.check(body)`
    /// before processing; `true` → dup, drop silently.
    /// `AgePastRequests` timer evicts old entries.
    pub(crate) seen: SeenRequests,

    /// Runtime annotation. Graph topology vs runtime state are
    /// different things: `tinc-graph::Node` is name + edges; this is
    /// which-conn-serves-it + the edge metadata `ack_h` builds.
    ///
    /// Only DIRECTLY-connected peers get a `NodeState` (via
    /// `on_ack`). Transitively-known nodes (learned from forwarded
    /// `ADD_EDGE`) are graph-only.
    ///
    /// Keyed by `NodeId`: tincd never calls `Graph::del_node`, so
    /// any `NodeId` is always live. Keying by the `Copy` ID kills
    /// the name→id→name double-lookup at every per-packet site.
    pub(crate) nodes: IntHashMap<NodeId, NodeState>,

    /// Per-edge address annotation. `tinc-graph::Edge` is topology-
    /// only (from/to/weight/options); the WIRE addresses live here.
    /// Split so the graph crate stays `#![no_std]`-clean.
    ///
    /// Stored as `(addr, port, local_addr, local_port)` raw `AddrStr`
    /// pairs (NOT parsed `SocketAddr`): `dump_edges` round-trips
    /// what arrived on the wire byte-exact.
    ///
    /// Populated by `on_ack` (direct edges) and `on_add_edge`
    /// (transitive). Cleaned up alongside `graph.del_edge`.
    pub(crate) edge_addrs: HashMap<EdgeId, (AddrStr, AddrStr, AddrStr, AddrStr)>,

    /// Per-packet state. Everything the hot loop touches lives here;
    /// everything the gossip/timer/meta-conn machinery touches lives
    /// in `Daemon` proper. The exception is `dp.tunnels`: gossip
    /// pokes it for `BecameReachable`/`Unreachable` transitions and
    /// `ans_key` handshake completion. `self.dp.tunnels` outside
    /// `net/` and `txpath` is the grep pattern for finding the
    /// boundary between gossip-triggered tunnel state changes and
    /// per-packet reads.
    pub(crate) dp: DataPlane,

    /// UDP fast-path lookup: every packet has `[dst_id6][src_id6]`
    /// prefix; receiver maps `src_id6` → `NodeId` to find which
    /// SPTPS state to feed. Populated
    /// alongside `node_ids` in `lookup_or_add_node`.
    pub(crate) id6_table: NodeId6Table,

    /// Incremented when a peer claims WE have an edge we don't.
    /// Read by `periodic_handler`: if it exceeds a threshold,
    /// log+restart. The contradiction means
    /// our world-view diverged from the mesh's badly enough that
    /// gossip won't converge.
    pub(crate) contradicting_add_edge: u32,
    /// Same, for `DEL_EDGE`: peer says we DON'T have an edge we DO have.
    pub(crate) contradicting_del_edge: u32,

    /// Set by `on_add_edge`; `flush_graph_dirty` runs the BFS once
    /// at the end of each dispatch batch instead of per edge.
    /// `on_del_edge`/`on_ack`/`terminate` still call
    /// `run_graph_and_log` directly (they read the result
    /// immediately) and that clears this too.
    pub(crate) graph_dirty: bool,

    /// Seconds the periodic handler blocks for when contradicting-
    /// edge counters exceed 100. The "two daemons fighting over the
    /// same Name" backoff: doubled each time it triggers (cap 3600),
    /// halved each clean period (floor 10). Default 10.
    pub(crate) sleeptime: u32,

    /// ICMP rate-limit time base. The limiter only compares for
    /// SAME-SECOND; any monotonic-integer source works. We use
    /// daemon-uptime seconds. Set at setup; never reset.
    pub(crate) started_at: Instant,

    /// Rate-limit state for ICMP error synthesis. Max 3/sec across
    /// ALL unreachable destinations.
    pub(crate) icmp_ratelimit: icmp::IcmpRateLimit,

    /// Laptop-suspend detector: if `now - this > 2 *
    /// udp_discovery_timeout`, the daemon was asleep - force-close
    /// every connection (the peers gave up on us; sending into stale
    /// SPTPS contexts produces "failed signature" noise on the other
    /// side). Updated each `on_ping_tick`.
    pub(crate) last_periodic_run_time: Instant,

    /// Kernel-chosen interface name (`tun0`, `tinc0`). Captured at
    /// setup from `device.iface()` because the trait borrow blocks
    /// `&mut self` at script call sites.
    pub(crate) iface: String,

    /// Off-loop FIFO executor for host/subnet hooks: slow scripts
    /// must not freeze the data plane on reachability flips.
    pub(crate) script_worker: crate::scriptworker::ScriptWorker,

    /// Derived, NOT a config var: `(device emits full eth frames) &&
    /// (Mode=router)`. Router-mode IGNORES MACs but the kernel
    /// doesn't - a TAP write with zero dst-MAC is dropped by the rx
    /// filter. Fix: snatch the kernel's MAC from its own ARP/NDP
    /// solicits, stamp it onto outgoing frames. See `mymac`.
    pub(crate) overwrite_mac: bool,

    /// The kernel's interface MAC. Seeded at setup (SIOCGIFHWADDR on
    /// Linux TAP), then REFRESHED on every ARP/NDP from the kernel -
    /// the eth-src of those frames IS the kernel's MAC. Init
    /// `{0xFE,0xFD,0,0,0,0}` (locally-administered placeholder).
    pub(crate) mymac: [u8; 6],

    /// Consecutive device-read failures. Reset on success. At 10:
    /// exit. A flapping TUN means the kernel device is gone;
    /// tight-looping forever helps nobody.
    pub(crate) device_errors: u32,

    /// One slot per `ConnectTo` in `tinc.conf`. Populated by
    /// `try_outgoing_connections` at setup. The mark-sweep only
    /// fires on SIGHUP-reload.
    pub(crate) outgoings: SlotMap<OutgoingId, Outgoing>,

    /// Per-outgoing retry timer. Kept parallel for the same layering
    /// reason as `conn_io`. `setup_outgoing_connection` disarms it
    /// first thing.
    pub(crate) outgoing_timers: slotmap::SecondaryMap<OutgoingId, TimerId>,

    /// Names of nodes whose `hosts/NAME` file has an `Address =`
    /// line. Populated by `load_all_nodes` at setup + reload. Read
    /// by `autoconnect::decide` (the eligible-to-dial gate).
    ///
    /// **Why a `HashSet`, not a `NodeState` field**: `NodeState` is
    /// direct-peers-only (allocated in `on_ack`). `has_address`
    /// applies to ANY node we have a hosts/ file for, including ones
    /// we've never connected to. `load_all_nodes` does add every
    /// hosts/-file name to the GRAPH so `node_ids` is the
    /// authoritative "nodes I know exist" set; this is just the
    /// `has_address` annotation on top.
    pub(crate) has_address: HashSet<String>,

    /// Names of nodes whose `hosts/NAME` file has an Ed25519 public
    /// key. Populated by `load_all_nodes`. Read by
    /// `autoconnect::decide` (widens the `has_address` dial-candidacy
    /// gate when `DhtDiscovery=yes`: a pubkey is enough to BEP44-
    /// resolve an address) and by the cold-start pre-resolve in
    /// `spawn_dht_discovery`.
    pub(crate) has_dht_key: HashSet<String>,

    /// Per-node "don't re-add as a shortcut before" stamp. Set in
    /// `execute_auto_action` on `Disconnect{AutoShortcut}` and
    /// `CancelPending` of a shortcut slot. Read by
    /// `decide_autoconnect`. Keyed by name (the node may not have a
    /// `TunnelState` after the conn drops).
    pub(crate) shortcut_backoff: HashMap<String, Instant>,

    /// Previous `decide_autoconnect` sample time, for the EWMA dt.
    /// `None` until the first periodic tick.
    pub(crate) last_autoconnect_tick: Option<Instant>,

    /// Last `sssp` result. Side table indexed by `NodeId.0` (same
    /// indexing as `sssp`'s output). `dump_nodes` reads this for
    /// the `nexthop`/`via`/`distance` columns. Updated by
    /// `run_graph_and_log`.
    ///
    /// `Arc`: `sssp` already builds a fresh `Vec` per BFS, so the
    /// swap is `Arc::new(routes)` — no copy-on-write, no in-place
    /// mutation. Reads deref through `Arc` transparently (zero
    /// hot-path cost: `*arc` is a pointer chase, same as `&Vec`).
    /// Clonable into a snapshot for the TX fast path.
    ///
    /// Not `ArcSwap`: the daemon's own loop is single-threaded, so
    /// the writer and reader are the same thread. The per-read
    /// fence in `ArcSwap::load()` measured -2.4% on the hot path
    /// for zero benefit.
    pub(crate) last_routes: Arc<Vec<Option<Route>>>,

    /// MST membership. We store the edge IDs and map at broadcast
    /// time (`NodeState.edge` is the conn→edge link). Populated by
    /// `run_graph()`.
    pub(crate) last_mst: Vec<EdgeId>,

    /// `route_mac`'s lookup table. `HashMap<Mac, owner-name>`.
    /// Maintained alongside `subnets`: every `Subnet::Mac` add/del
    /// also updates this. `route_mac.rs` takes the flat map directly
    /// (testability - see `route_mac.rs` doc). Five sync sites: `learn_mac`,
    /// `on_age_subnets`, `on_add_subnet`, `on_del_subnet`, reload.
    pub(crate) mac_table: HashMap<route_mac::Mac, String>,

    /// Expiry tracker for OUR learned MACs (those owned by
    /// `myself`). NOT all MAC subnets - peers' learned MACs are in
    /// `mac_table` (via gossip `ADD_SUBNET`) but not here. Lifecycles
    /// kept separate (see `mac_lease.rs` doc).
    pub(crate) mac_leases: mac_lease::MacLeases,

    /// Log-once latch for the `MAX_MAC_LEASES` cap in `learn_mac`.
    pub(crate) mac_cap_warned: bool,

    /// Lazy-created on the first `learn()` (when `learn()` returns
    /// `true` = "table was empty"). `Option` skips an idempotency
    /// check.
    pub(crate) age_subnets_timer: Option<TimerId>,

    // ─── settings
    /// The config knobs. Reload swaps this.
    pub(crate) settings: DaemonSettings,

    /// Tracks whether `device_enable()` (tinc-up) has fired.
    /// When `device_standby`, tinc-up fires on first reachable peer,
    /// tinc-down on last unreachable. This bool prevents double-fire
    /// (we process transitions one-by-one not in a batch - simpler
    /// to track explicitly than to do exact-count arithmetic).
    pub(crate) device_enabled: bool,

    // ─── event loop machinery
    /// epoll + slot table. Generic over `IoWhat`.
    pub(crate) ev: EventLoop<IoWhat>,
    /// Timer wheel. Generic over `TimerWhat`.
    pub(crate) timers: Timers<TimerWhat>,
    /// Self-pipe + handler table. Generic over `SignalWhat`.
    pub(crate) signals: SelfPipe<SignalWhat>,
    /// Kept so the match arm can re-arm.
    pub(crate) pingtimer: TimerId,
    /// Re-arms +10s.
    pub(crate) age_timer: TimerId,
    /// Re-arms +5s.
    pub(crate) periodictimer: TimerId,
    /// Re-arms +`keylifetime`.
    pub(crate) keyexpire_timer: TimerId,
    /// `sd_notify(WATCHDOG=1)` timer + interval. `None` when not
    /// running under a systemd unit with `WatchdogSec=` (the env
    /// var was unset). The interval is cached so the match arm can
    /// re-arm without re-reading env.
    pub(crate) watchdog: Option<(TimerId, Duration)>,

    /// Loaded from `confbase/invitations/ed25519_key.priv`. `None`
    /// when no invitations have been issued (the file doesn't
    /// exist) - the `?` greeting is then rejected at `id_h`.
    /// Re-loaded on SIGHUP.
    pub(crate) invitation_key: Option<SigningKey>,

    /// mtime threshold for `conns_to_terminate`. Initialized to
    /// daemon-start time; first SIGHUP compares against start.
    pub(crate) last_config_check: SystemTime,

    /// The loop condition. Handlers set `running = false`; the loop
    /// checks before each iteration.
    pub(crate) running: bool,

    /// Cheap gate before `send_pcap`. Armed by `REQ_PCAP`. LAZILY
    /// recomputed inside `send_pcap` itself: the loop sets it false,
    /// then back to true if any conn still wants it. So a pcap
    /// subscriber dropping its connection costs ONE extra
    /// `send_pcap` walk - `terminate()` doesn't need to know about
    /// pcap.
    pub(crate) any_pcap: bool,

    /// DHT actor. `Some` iff `dht_discovery` set and spawn succeeded.
    /// Polled from `on_periodic_tick`; drop joins the thread.
    pub(crate) discovery: Option<crate::discovery::Discovery>,

    /// Off-thread `getaddrinfo`. Owns the only call sites that hit
    /// libc DNS after setup. Drained in `on_periodic_tick`.
    pub(crate) dns_worker: crate::bgresolve::DnsWorker,

    /// Off-thread DNS results for `Address=` hostnames, by node name.
    /// Chained into `addr_cache.known` alongside edge-walk + DHT hints
    /// in `setup_outgoing_connection`. Cleared on `retry_outgoing` so
    /// each round re-resolves (dynamic DNS).
    pub(crate) dns_hints: HashMap<String, Vec<SocketAddr>>,

    /// Resolved SOCKS/HTTP proxy address(es). Empty until the worker
    /// answers (or after a failed lookup) — callers don't distinguish
    /// "pending" from "NXDOMAIN", they just retry. `do_outgoing_
    /// connection` dials `[0]`.
    pub(crate) proxy_addrs: Vec<SocketAddr>,

    /// DHT-resolved addrs by node name. Separate map, not stuffed into
    /// `addr_cache.known`: the edge-walk replaces `known` wholesale on
    /// every retry; we merge at read time in `setup_outgoing_connection`.
    pub(crate) dht_hints: HashMap<String, Vec<SocketAddr>>,

    /// Port-probe demux gate (≤3 entries). Cleared/repopulated each
    /// round so stale targets don't latch a late reply. Why source addr,
    /// not packet shape: see `handle_incoming_vpn_packet`.
    pub(crate) dht_probe_sent: HashSet<SocketAddr>,

    /// UPnP-IGD/NAT-PMP refresh thread (Rust port of C `upnp.c`).
    /// `Some` iff `UPnP != no` and the feature is compiled in. Polled
    /// from `on_periodic_tick`; the TCP `Mapped` event feeds
    /// `discovery.set_portmapped_tcp` so the BEP44 record gains a
    /// dialable `tcp=` field.
    #[cfg(feature = "upnp")]
    pub(crate) portmapper: Option<crate::portmap::Portmapper>,

    /// TX fast-path snapshot. The Super arm `mem::take`s this,
    /// calls `tx_probe(&snap, ...)`, runs the seal-send loop on
    /// `Some`, restores. `None` until setup finishes; `Default` for
    /// `mem::take`.
    pub(crate) tx_snap: Option<crate::shard::TxSnapshot>,

    /// Per-peer fast-path handles. Same `Arc` as in `tx_snap.tunnels`;
    /// kept here so `minmtu`/`udp_addr` updates have a place to
    /// write without `mem::take`-ing the snapshot. `store(Relaxed)`
    /// here is visible to the next `tx_probe`'s `load(Relaxed)` — no
    /// fence, no fan-out, no wake. Populated at `HandshakeDone`;
    /// cleared at `BecameUnreachable`.
    pub(crate) tunnel_handles: IntHashMap<NodeId, Arc<crate::shard::TunnelHandles>>,
}

impl Daemon {
    /// Persisted DHT routing table. Same writable-dir rule as the
    /// addrcache: `$STATE_DIRECTORY/addrcache` (the one subdir we
    /// chown + Landlock-allow) else `confbase`.
    pub(crate) fn dht_nodes_path(&self) -> PathBuf {
        std::env::var_os("STATE_DIRECTORY")
            .map_or_else(
                || self.confbase.clone(),
                |s| PathBuf::from(s).join("addrcache"),
            )
            .join("dht_nodes")
    }

    /// Refresh the TX snapshot's subnet trie. Called after each
    /// `subnets.add()`/`del()` (gossip, MAC lease, purge, reload).
    /// Clones the `BTreeMap` (O(n) String clones); subnet churn is
    /// gossip-rate, not packet-rate. No-op until setup builds the
    /// snapshot — setup runs the script subnet adds before that point,
    /// and the snapshot's initial clone covers them.
    pub(super) fn tx_snap_refresh_subnets(&mut self) {
        if let Some(s) = self.tx_snap.as_mut() {
            s.subnets = Arc::new(self.subnets.clone());
        }
    }

    /// Refresh routes + node view. Called at the END of
    /// `run_graph_and_log` (after the transition loop, so `reachable`
    /// is post-BFS) and after `purge` (the only path that removes from
    /// `node_ids` without a follow-up BFS). `last_routes.len()` is the
    /// graph slab length — same indexing invariant as `route_of`.
    pub(super) fn tx_snap_refresh_graph(&mut self) {
        if let Some(s) = self.tx_snap.as_mut() {
            s.routes = Arc::clone(&self.last_routes);
            s.ns = Arc::new(crate::shard::NodeView::build(
                &self.graph,
                &self.node_ids,
                &self.nodes,
                self.last_routes.len(),
            ));
            // id6_table changes at the same sites that change
            // node_ids: lookup_or_add_node (gossip.rs:33) and purge
            // (purge.rs:164). Both already call this hook. The
            // periodic.rs `load_all_nodes` reload doesn't add new
            // node_ids (it only reads hosts/ for subnets), so it
            // doesn't change id6_table either. One clone covers all.
            s.id6 = Arc::new(self.id6_table.clone());
        }
    }
}

impl Daemon {
    /// Node name for logging. tincd never calls `Graph::del_node`
    /// (only `del_edge`; nodes accumulate monotonically), so any
    /// `NodeId` obtained from `node_ids`, `id6_table`, `last_routes`,
    /// or an `Edge`'s endpoints is always live. The `<gone>`
    /// fallback never fires - it exists because `Graph::node`
    /// returns `Option` (the graph crate doesn't know tincd's
    /// monotonic-node usage).
    pub(super) fn node_log_name(&self, nid: NodeId) -> &str {
        self.graph.node(nid).map_or("<gone>", |n| n.name.as_str())
    }

    /// Panics if `id` is not in the slotmap. Callers hold an id obtained
    /// from a live dispatch and must not have `terminate()`d it since.
    #[inline]
    pub(super) fn conn_mut(&mut self, id: ConnId) -> &mut Connection {
        self.conns.get_mut(id).expect("ConnId not live")
    }

    #[inline]
    pub(super) fn conn(&self, id: ConnId) -> &Connection {
        self.conns.get(id).expect("ConnId not live")
    }

    /// The `while(running)` loop. `tinc-event` deliberately doesn't
    /// have this; `turn()` is one iteration. This is the stitch.
    ///
    /// Consumes `self` - the loop runs once, then teardown is `Drop`.
    ///
    /// ```text
    /// while running:
    ///     timeout = timers.tick(fired_timers)
    ///     for t in fired_timers: dispatch_timer(t)
    ///     ev.turn(timeout, fired_io)               ─ epoll_wait
    ///     for (w, ready) in fired_io: dispatch_io
    /// ```
    ///
    /// Timers FIRST: pingtimer might close a connection; that
    /// connection then doesn't show up as readable. "Fire timers,
    /// THEN compute timeout" so a timer that re-arms itself yields
    /// the correct next deadline.
    ///
    /// `timeout = None` means block forever - only safe because
    /// `tick()` returns `None` precisely when no timers are armed,
    /// and we always re-arm. `epoll_wait(-1)` blocks forever.
    #[must_use]
    pub fn run(mut self) -> RunOutcome {
        // Reusable buffers. `tick`/`turn`/`drain` clear these
        // before pushing.
        let mut fired_timers = Vec::with_capacity(8);
        let mut fired_io = Vec::with_capacity(tinc_event::MAX_EVENTS_PER_TURN);
        let mut fired_signals = Vec::with_capacity(4);

        while self.running {
            // ─── timers
            // tick(): cache `now`, drain expired. Ignore returned
            // deadline — handlers below re-arm, recompute after.
            let _ = self.timers.tick(&mut fired_timers);
            for &t in &fired_timers {
                match t {
                    TimerWhat::Ping => self.on_ping_tick(),
                    TimerWhat::AgePastRequests => self.on_age_past_requests(),
                    TimerWhat::RetryOutgoing(oid) => {
                        self.setup_outgoing_connection(oid);
                    }
                    TimerWhat::Periodic => {
                        // Return is the would-sleep duration; only
                        // the unit test reads it.
                        let _ = self.on_periodic_tick();
                    }
                    TimerWhat::AgeSubnets => {
                        self.on_age_subnets();
                    }
                    TimerWhat::KeyExpire => {
                        self.on_keyexpire();
                    }
                    TimerWhat::Watchdog => {
                        crate::sd_notify::notify_watchdog();
                        if let Some((tid, iv)) = self.watchdog {
                            self.timers.set(tid, iv);
                        }
                    }
                }
            }

            // ─── poll
            // Recompute after dispatch (handlers re-arm). Floor 1ms:
            // sub-ms rounds to epoll_wait(0) and spins; all timers
            // here are second-granularity so the slop is invisible.
            // No drain→dispatch loop — re-arm-at-now would livelock.
            let timeout = self
                .timers
                .next_timeout()
                .map(|d| d.max(Duration::from_millis(1)));
            if let Err(e) = self.ev.turn(timeout, &mut fired_io) {
                log::error!(target: "tincd",
                            "Error while waiting for input: {e}");
                return RunOutcome::PollError;
            }

            // ─── io dispatch
            for &(what, ready) in &fired_io {
                match what {
                    IoWhat::Signal => {
                        // drain reads ALL pending bytes (signals
                        // coalesce in the pipe).
                        self.signals.drain(&mut fired_signals);
                        for &s in &fired_signals {
                            self.on_signal(s);
                        }
                        fired_signals.clear();
                    }

                    IoWhat::UnixListener => {
                        self.on_unix_accept();
                    }

                    IoWhat::Conn(id) => {
                        // The connection might have been terminated
                        // by an EARLIER event in this same batch
                        // (e.g., pingtimer closed it). Stale key →
                        // None: the generation guard.
                        if !self.conns.contains_key(id) {
                            continue;
                        }
                        // Connecting check FIRST. The async-connect
                        // probe. On success FALL THROUGH to the
                        // write/read dispatch — the socket is
                        // writable now and the ID line is queued; do
                        // the flush in the same wake instead of
                        // costing another loop iteration. Under LT
                        // epoll this is an optimisation, not a
                        // correctness requirement (a `continue` would
                        // re-fire on the next `turn()` since the fd
                        // is still writable). Probe-spurious and
                        // probe-fail paths DO return; probe-success
                        // falls through.
                        if self.conns[id].connecting {
                            if !self.on_connecting(id) {
                                // Spurious / failed.
                                continue;
                            }
                            // Success: fall through. The ID line is
                            // queued; flush it now (outbuf nonempty
                            // → `on_conn_writable`). The conn might
                            // have been terminated by an io_set
                            // failure inside finish_connecting.
                            if !self.conns.contains_key(id) {
                                continue;
                            }
                        }
                        // Write before read. tinc-event already orders
                        // WRITE-before-READ in the per-fd event pair.
                        if matches!(ready, Ready::Write) {
                            self.on_conn_writable(id);
                        } else {
                            self.on_conn_readable(id);
                        }
                    }

                    IoWhat::Device => {
                        // Edge-triggered: drain until EAGAIN.
                        self.on_device_read();
                    }

                    IoWhat::Tcp(i) => {
                        self.on_tcp_accept(i);
                    }

                    IoWhat::Udp(i) => {
                        self.on_udp_recv(i);
                    }
                }
            }

            // ─── log tap drain
            // The `log::Log` impl is `'static` and can't reach
            // `&mut self.conns`. It pushes to a thread-local buffer;
            // drain here. Once-per-turn batching is fine: log lines
            // accumulate in outbuf until the next WRITE event anyway.
            self.flush_log_tap();
        }

        log::info!(target: "tincd", "Terminating");
        RunOutcome::Clean
    }

    // ─── timer handlers
}

impl Drop for Daemon {
    /// Unlink pidfile + socket. `ControlSocket::drop` already
    /// unlinks the socket; we do the pidfile.
    fn drop(&mut self) {
        // Subnet-down first (may `ip route del`), THEN tinc-down
        // (brings the iface down). Mirror of the setup-time
        // subnet-up loop.
        for s in &self.subnets.owned_by(&self.name) {
            self.run_subnet_script_sync(false, &self.name, s);
        }

        // tinc-down BEFORE device close (the device's own `Drop`
        // runs after). Gate on whether tinc-up actually fired -
        // more correct than checking `!device_standby`: if standby
        // and a peer was reachable at shutdown, we don't run graph
        // in Drop, so check the actual state.
        if self.device_enabled {
            self.run_script("tinc-down");
        }
        // Persist the DHT routing table so the next start can skip
        // the DNS-seed round-trip. Same lifecycle as the addrcache
        // (written from Drop, post-drop_privs ownership). Mainline's
        // actor thread is still alive until `self.discovery` drops
        // below, so `to_bootstrap()` works.
        if let Some(d) = &self.discovery {
            let nodes = d.routing_nodes();
            if !nodes.is_empty()
                && let Err(e) =
                    crate::discovery::save_persisted_nodes(&self.dht_nodes_path(), &nodes)
            {
                log::debug!(target: "tincd::discovery",
                            "dht_nodes save failed: {e}");
            }
        }
        let _ = std::fs::remove_file(&self.pidfile);
        // Signal handlers stay installed (SelfPipe::drop doesn't del
        // them - see tinc-event/sig.rs Drop doc). Process is exiting;
        // doesn't matter.
    }
}

/// Why `Daemon::setup` failed.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// Config read/parse error, or required field missing.
    #[error("{0}")]
    Config(String),
    /// OS resource: socket, file, epoll. `what` says WHICH resource
    /// so an EACCES from TUN open is distinguishable from one from
    /// pidfile write — the bare errno alone leaves the operator
    /// guessing.
    #[error("{what}: {source}")]
    Io {
        /// Human label for the failing operation.
        what: String,
        /// Underlying errno.
        #[source]
        source: std::io::Error,
    },
}

impl SetupError {
    /// Tag an I/O error with the operation that produced it.
    pub(crate) fn io(what: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            what: what.into(),
            source,
        }
    }
}

// tests
//
// `setup()` and `run()` are NOT unit-testable: SelfPipe is a process
// singleton, signal handlers are process-global. The integration test
// (tests/stop.rs) does the real thing in a subprocess.
//
// What IS testable here: the small pieces that don't touch signals.
// terminate's coherence (conns + conn_io stay in sync), the IoWhat/
// TimerWhat enum shapes.

#[cfg(test)]
mod tests {
    use super::*;

    /// Rate limit on the Unreachable arm. Max 3/sec. Can't
    /// construct a full `Daemon` (`SelfPipe` singleton); test the
    /// `IcmpRateLimit` directly with the same `freq=3` the daemon
    /// uses. The wiring (daemon-uptime-secs as the key) is
    /// exercised by the `real_tun_unreachable` netns test.
    #[test]
    fn ratelimit_drops_after_3() {
        let mut rl = icmp::IcmpRateLimit::new();
        // Same second: first 3 pass, 4th drops.
        assert!(!rl.should_drop(42, 3));
        assert!(!rl.should_drop(42, 3));
        assert!(!rl.should_drop(42, 3));
        assert!(rl.should_drop(42, 3), "4th call same-sec must drop");
        assert!(rl.should_drop(42, 3), "5th call same-sec still drops");
        // Next second: counter resets.
        assert!(!rl.should_drop(43, 3));
    }

    /// `periodic_handler` backoff arithmetic. Can't construct a
    /// full `Daemon` (`SelfPipe` is process-singleton); test the math
    /// on a fake. The function is
    /// extracted so the storm-detection arithmetic is checkable
    /// without sleeping.
    ///
    /// Mirrors `on_periodic_tick`'s body. Any divergence between
    /// this and the real fn would be caught by the integration
    /// test (which doesn't exist for the storm case - hard to
    /// induce). The arithmetic IS the easy bit; pin it.
    #[test]
    fn periodic_contradicting_edge_backoff() {
        // Same arithmetic as `on_periodic_tick`.
        fn step(add: u32, del: u32, sleeptime: u32) -> (u32, Duration) {
            if del > 100 && add > 100 {
                let d = Duration::from_secs(u64::from(sleeptime));
                (sleeptime.saturating_mul(2).min(3600), d)
            } else {
                ((sleeptime / 2).max(10), Duration::ZERO)
            }
        }

        // Clean period: halve, floor at 10.
        assert_eq!(step(0, 0, 10), (10, Duration::ZERO));
        assert_eq!(step(0, 0, 100), (50, Duration::ZERO));
        assert_eq!(step(0, 0, 11), (10, Duration::ZERO)); // 5 → floor
        // BOTH must exceed 100.
        assert_eq!(step(101, 50, 10), (10, Duration::ZERO));
        assert_eq!(step(50, 101, 10), (10, Duration::ZERO));

        // Storm: sleep `sleeptime`, then double.
        assert_eq!(step(101, 101, 10), (20, Duration::from_secs(10)));
        assert_eq!(step(101, 101, 20), (40, Duration::from_secs(20)));
        // Cap at 3600.
        assert_eq!(step(101, 101, 2000), (3600, Duration::from_secs(2000)));
        assert_eq!(step(101, 101, 3600), (3600, Duration::from_secs(3600)));
    }
}
