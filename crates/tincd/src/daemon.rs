//! `Daemon` — all the C-global state as one struct, plus the main loop.
//!
//! Loop shape: tick → turn → match. `IoWhat` is the `W` in
//! `EventLoop<W>`. `run()` consumes `self`; teardown is `Drop`.

use std::collections::{HashMap, HashSet};

use crate::inthash::IntHashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use slotmap::{SlotMap, new_key_type};
use tinc_crypto::sign::SigningKey;
use tinc_device::{Device, DeviceArena, GroBucket};
use tinc_event::{EventLoop, Ready, SelfPipe, TimerId, Timers};
use tinc_graph::{EdgeId, Graph, NodeId, Route};
use tinc_proto::AddrStr;

use crate::conn::Connection;
use crate::control::ControlSocket;
use crate::egress::{TxBatch, UdpEgress};
use crate::listen::{Listener, Tarpit};
use crate::node_id::NodeId6Table;
use crate::outgoing::{Outgoing, OutgoingId};
use crate::seen::SeenRequests;
use crate::subnet_tree::SubnetTree;
use crate::tunnel::TunnelState;
use crate::{compress, icmp, mac_lease, route_mac};

mod connect;
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
pub use settings::{DaemonSettings, ForwardingMode, RoutingMode};
pub(crate) use settings::{
    apply_reloadable_settings, parse_connect_to_from_config, parse_subnets_from_config,
};

// SPTPS record-type bits for the per-tunnel data channel.
// Type 0 = plain IP packet (router mode, no compression). Bits OR.
const PKT_NORMAL: u8 = 0;
const PKT_COMPRESSED: u8 = 1;
const PKT_MAC: u8 = 2;
const PKT_PROBE: u8 = 4;

// dispatch enums - the W in EventLoop<W> / Timers<W> / SelfPipe<W>

new_key_type! {
    /// Connection handle. Generational: stale id → `conns.get(id) == None`.
    pub struct ConnId;
}

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
    #[allow(dead_code)]
    UdpPing,
}

/// TERM/QUIT/INT all map to Exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalWhat {
    /// SIGHUP.
    Reload,
    /// SIGTERM/INT/QUIT.
    Exit,
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

    /// `choose_udp_address` cycle counter. 2-of-3 calls explore an
    /// edge address; 1-of-3 sticks with the reflexive. NOT random -
    /// a strict cycle. One global counter, not per-node.
    pub(crate) choose_udp_x: u8,

    /// Data-plane half. Separate from `nodes`/`NodeState` because
    /// the lifecycles differ - `TunnelState` exists for ANY
    /// reachable node (we send UDP to nodes we have no TCP
    /// connection to, forwarding the handshake via nexthop's conn).
    ///
    /// `entry().or_default()` lazy-init: a node learned from
    /// `ADD_EDGE` has no tunnel until `send_req_key` starts one.
    pub(crate) tunnels: IntHashMap<NodeId, TunnelState>,

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

    /// Per-daemon compression workspace. Currently a ZST (`lz4_flex`
    /// is stateless, zlib one-shot per call); kept as a struct so
    /// adding persistent `z_stream` state doesn't churn wire-up sites.
    pub(crate) compressor: compress::Compressor,

    /// Reused send-side scratch for the UDP data path. `seal_data_into`
    /// writes `[0;12] ‖ SPTPS-datagram` here; `send_sptps_data_relay`
    /// then overwrites the 12-byte prefix with `[dst_id6 ‖ src_id6]`
    /// in-place and `sendto`s the whole thing. Cleared (not freed)
    /// between packets - after the first packet at MTU, capacity is
    /// `12 + MTU + 21` and stays there. Net: zero allocs on the
    /// per-packet send path. Can't VLA in Rust; a daemon-owned Vec
    /// is the closest equivalent to a stack arena.
    pub(crate) tx_scratch: Vec<u8>,

    /// Inner-packet TOS set by `route_packet`, read by the UDP send
    /// path. The daemon is single-threaded so a field works in lieu
    /// of threading it via a packet struct. Reset to 0 at the top of
    /// each `route_packet`.
    pub(crate) tx_priority: u8,

    /// Reused recv-side scratch for the UDP data path. Mirror of
    /// `tx_scratch`. `open_data_into` writes `[0;14] ‖ decrypted-body`
    /// here; `receive_sptps_record_fast` then overwrites `[12..14]` with
    /// the synthesized ethertype in-place and routes the whole slice.
    /// Cleared (not freed) between packets - after the first packet at
    /// MTU, capacity is `14 + MTU` and stays there. Net: zero allocs on
    /// the per-packet receive path.
    pub(crate) rx_scratch: Vec<u8>,

    /// recvmmsg batch state (~108KB). Heap-allocated once at setup.
    /// `Option` so `on_udp_recv` can `mem::take` it (the bufs borrow
    /// fights `&mut self` for `handle_incoming_vpn_packet`; same
    /// dance as `rx_scratch`).
    pub(crate) udp_rx_batch: Option<net::UdpRxBatch>,

    /// GRO TUN-write coalescer (`RUST_REWRITE_10G.md`).
    /// `recvmmsg_batch` arms it; `send_packet_myself` offers each
    /// inbound-for-us packet; the post-dispatch flush ships the
    /// super. Same `mem::take`-out-of-self dance as `rx_scratch`
    /// (`send_packet_myself` is `&mut self` and the bucket borrow
    /// would conflict). `None` outside the batch loop - the send
    /// site checks: `Some` ⇒ try coalesce, `None` ⇒ immediate write
    /// (the ICMP-reply / broadcast-echo / kernel-mode paths, which
    /// hit `send_packet_myself` outside any UDP recv batch).
    pub(crate) gro_bucket: Option<GroBucket>,

    /// Persistent backing for `gro_bucket`. `GroBucket::new()` heap-
    /// allocs 64KB; doing that per recvmmsg batch (the original
    /// `then(GroBucket::new)` sketch) would be ~10k allocs/sec at
    /// line rate. Same heap-once pattern as `udp_rx_batch`.
    /// `recvmmsg_batch` parks it in `gro_bucket` for the dispatch
    /// loop, then puts it back here. `flush()` resets internal
    /// state; the 64KB stays.
    pub(crate) gro_bucket_spare: Option<GroBucket>,

    /// Whether `device.write_super()` works. Linux TUN with
    /// `IFF_VNET_HDR` (the only backend that overrides the trait
    /// default). Captured at setup so the hot path doesn't dyn-
    /// dispatch a `mode()` call per packet.
    pub(crate) gro_enabled: bool,

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

    /// Slot arena for `Device::drain` (`RUST_REWRITE_10G.md`).
    /// Replaces `on_device_read`'s 1.5KB stack buf: drain reads
    /// frames into slots, the loop body walks them. Read-side only;
    /// `tx_scratch` handles the encrypt path (separate buffers,
    /// no overlap).
    ///
    /// `Option` for the same `mem::take` dance as `udp_rx_batch`:
    /// `route_packet` borrows `&mut self`; the arena slot borrow
    /// conflicts. Take, walk, put back.
    pub(crate) device_arena: Option<DeviceArena>,

    /// `tso_split` output scratch.
    /// `DrainResult::Super` means the device put a ≤64KB IP super-
    /// segment in `device_arena`; `tso_split` writes N × ~1500B
    /// eth frames into THIS buffer (the input slice can't overlap
    /// the output - same arena would alias). Same `mem::take` dance:
    /// `route_packet` borrows `&mut self`, the slot borrow conflicts.
    ///
    /// Sized at `DEVICE_DRAIN_CAP * STRIDE` = 64*1600 = 100KB. A
    /// 64KB super-segment at MSS 1400 = 47 segments; fits with room.
    /// `None` until the first `Super` arrives (the non-vnet path
    /// never allocates this).
    pub(crate) tso_scratch: Option<Box<[u8]>>,

    /// Per-segment lengths from `tso_split`. Same lifetime as
    /// `tso_scratch`; same lazy alloc.
    pub(crate) tso_lens: Box<[usize]>,

    /// TX batch accumulator (`RUST_REWRITE_10G.md`). The
    /// `on_device_read` drain loop stages encrypted frames here
    /// instead of `sendto`-per-frame; one `EgressBatch` ships the
    /// run after the loop. `None` outside the drain loop - the send
    /// site (`send_sptps_data_relay`) checks: `Some` ⇒ stage,
    /// `None` ⇒ immediate send (still hit by UDP-recv → forward,
    /// meta-conn → relay, probe sends).
    ///
    /// `Option` not for `mem::take` (it's never borrowed across a
    /// `&mut self` call) but as the in-batch-loop signal. The drain
    /// loop sets `Some` before walking slots, ships + sets `None`
    /// after.
    pub(crate) tx_batch: Option<TxBatch>,

    /// One slot per `ConnectTo` in `tinc.conf`. Populated by
    /// `try_outgoing_connections` at setup. The mark-sweep only
    /// fires on SIGHUP-reload.
    pub(crate) outgoings: SlotMap<OutgoingId, Outgoing>,

    /// Per-outgoing retry timer. Kept parallel for the same layering
    /// reason as `conn_io`. `setup_outgoing_connection` disarms it
    /// first thing.
    pub(crate) outgoing_timers: slotmap::SecondaryMap<OutgoingId, TimerId>,

    /// In-flight outgoing connect: socket NOT YET in `Connection`.
    /// The async-connect dance keeps the `socket2::Socket` for the
    /// `send(NULL,0,0)` probe and `take_error()` (which need the wrapper, not the raw fd). Once the
    /// probe succeeds, the `Socket` is consumed into the `Connection`
    /// fd. Keyed by `ConnId` (the connection slot is allocated
    /// fd-less at dial time; this map fills it).
    pub(crate) connecting_socks: slotmap::SecondaryMap<ConnId, socket2::Socket>,

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

    /// Last `sssp` result. Side table indexed by `NodeId.0` (same
    /// indexing as `sssp`'s output). `dump_nodes` reads this for
    /// the `nexthop`/`via`/`distance` columns. Updated by
    /// `run_graph_and_log`.
    pub(crate) last_routes: Vec<Option<Route>>,

    /// MST membership. We store the edge IDs and map at broadcast
    /// time (`NodeState.edge` is the conn→edge link). Populated by
    /// `run_graph()`.
    pub(crate) last_mst: Vec<EdgeId>,

    /// `route_mac`'s lookup table. `HashMap<Mac, owner-name>`.
    /// Maintained alongside `subnets`: every `Subnet::Mac` add/del
    /// also updates this. `SubnetTree::lookup_mac` exists but
    /// `route_mac.rs` takes the flat map directly (testability -
    /// see `route_mac.rs` doc). Five sync sites: `learn_mac`,
    /// `on_age_subnets`, `on_add_subnet`, `on_del_subnet`, reload.
    pub(crate) mac_table: HashMap<route_mac::Mac, String>,

    /// Expiry tracker for OUR learned MACs (those owned by
    /// `myself`). NOT all MAC subnets - peers' learned MACs are in
    /// `mac_table` (via gossip `ADD_SUBNET`) but not here. Lifecycles
    /// kept separate (see `mac_lease.rs` doc).
    pub(crate) mac_leases: mac_lease::MacLeases,

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

    /// DHT-resolved addrs by node name. Separate map, not stuffed into
    /// `addr_cache.known`: the edge-walk replaces `known` wholesale on
    /// every retry; we merge at read time in `setup_outgoing_connection`.
    pub(crate) dht_hints: HashMap<String, Vec<SocketAddr>>,

    /// Port-probe demux gate (≤3 entries). Cleared/repopulated each
    /// round so stale targets don't latch a late reply. Why source addr,
    /// not packet shape: see `handle_incoming_vpn_packet`.
    pub(crate) dht_probe_sent: HashSet<SocketAddr>,
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
            // tick(): cache `now`, drain expired, return next deadline.
            let timeout = self.timers.tick(&mut fired_timers);
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
                    TimerWhat::UdpPing => {
                        // Not armed yet. Unreachable.
                        unreachable!("timer {t:?} not armed yet")
                    }
                }
            }

            // ─── poll
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
            self.run_subnet_script(false, &self.name, s);
        }

        // tinc-down BEFORE device close (the device's own `Drop`
        // runs after). Gate on whether tinc-up actually fired -
        // more correct than checking `!device_standby`: if standby
        // and a peer was reachable at shutdown, we don't run graph
        // in Drop, so check the actual state.
        if self.device_enabled {
            self.run_script("tinc-down");
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
    /// OS resource: socket, file, epoll.
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),
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
    use std::time::Duration;

    /// `IoWhat` is `Copy`. `EventLoop<W: Copy>` requires it; this
    /// pins it. Adding a non-Copy field to `IoWhat` (like a String)
    /// fails here, before someone tries to use the daemon.
    #[test]
    fn iowhat_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<IoWhat>();
        assert_copy::<TimerWhat>();
        assert_copy::<SignalWhat>();
    }

    /// `ConnId` is `Copy` (slotmap keys are). `IoWhat::Conn(ConnId)`
    /// transitively needs this.
    #[test]
    fn connid_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ConnId>();
    }

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

    /// The `IoWhat` enum has all six variants. Compile-time check:
    /// adding a 7th without updating `run()` won't compile.
    #[test]
    fn iowhat_variant_census() {
        // Just match exhaustively. Compiler check, not runtime.
        fn _exhaustive(w: IoWhat) {
            match w {
                IoWhat::Signal
                | IoWhat::UnixListener
                | IoWhat::Device
                | IoWhat::Conn(_)
                | IoWhat::Tcp(_)
                | IoWhat::Udp(_) => {}
            }
        }
        // 6 variants. Can't introspect the count at runtime in
        // stable Rust without a macro. The match-exhaustiveness IS
        // the test.
    }
}
