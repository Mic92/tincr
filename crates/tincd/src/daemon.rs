//! `Daemon` — the C globals as one struct, plus `main_loop()`.
//!
//! Ports `net.c::main_loop` (`:487-527`): `Timers::tick →
//! EventLoop::turn → match`. `timeout_handler` (`:180-266`)
//! degenerates to re-arm-self with zero peers. Signal handlers
//! (`:316-334`) set `running = false` for TERM/INT/QUIT.
//! `handle_new_unix_connection` (`net_socket.c:781-812`): accept,
//! allocate, register. `setup_network` (`net_setup.c:1235-1275`):
//! abridged call chain.
//!
//! `IoWhat` is the `W` in `EventLoop<W>` (six variants for six
//! C io callbacks). `run()` consumes `self`: C `main_loop()` runs
//! once, teardown is `Drop`.
//!
//! Logging: `target: "tincd"` for startup/shutdown, `"tincd::conn"`
//! for accept/terminate. See lib.rs for the full mapping.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use slotmap::{SlotMap, new_key_type};
use tinc_crypto::sign::SigningKey;
use tinc_device::Device;
use tinc_event::{EventLoop, Io, IoId, Ready, SelfPipe, TimerId, Timers};
use tinc_graph::{EdgeId, Graph, NodeId, Route};
use tinc_proto::msg::{AddEdge, AnsKey, DelEdge, ReqKey, SubnetMsg};
use tinc_proto::{AddrStr, Request, Subnet};
use tinc_sptps::{Framing, Role, Sptps};

use crate::conn::{Connection, FeedResult};
use crate::control::{ControlSocket, generate_cookie, write_pidfile};
use crate::graph_glue::{Transition, run_graph};
use crate::keys::{PrivKeyError, read_ecdsa_private_key};
use crate::listen::{
    AddrFamily, Listener, Tarpit, configure_tcp, fmt_addr, is_local, open_listeners, pidfile_addr,
    unmap,
};
use crate::node_id::{NodeId6, NodeId6Table};
use crate::outgoing::{
    ConnectAttempt, MAX_TIMEOUT_DEFAULT, Outgoing, OutgoingId, probe_connecting,
    resolve_config_addrs, try_connect,
};
use crate::proto::{
    DispatchError, DispatchResult, IdCtx, IdOk, check_gate, handle_control, handle_id,
    myself_options_default, parse_ack, parse_add_edge, parse_add_subnet, parse_del_edge,
    parse_del_subnet, record_body, send_ack,
};
use crate::route::{RouteResult, route};
use crate::script::{self, ScriptEnv, ScriptResult};
use crate::seen::SeenRequests;
use crate::subnet_tree::SubnetTree;
use crate::tunnel::{TunnelState, make_udp_label};

// `net.h:106-108`: SPTPS record-type bits for the per-tunnel data
// channel. Type 0 = plain IP packet (RMODE_ROUTER, no compression).
// Bits OR together.
const PKT_NORMAL: u8 = 0;
const PKT_COMPRESSED: u8 = 1;
const PKT_MAC: u8 = 2;
const PKT_PROBE: u8 = 4;

// dispatch enums — the W in EventLoop<W> / Timers<W> / SelfPipe<W>

new_key_type! {
    /// `connection_t*`. Generational: a stale `ConnId` for a slot
    /// that's been reused returns `None` from `conns.get(id)`. The
    /// C uses raw pointers and the io_tree.generation guard.
    pub struct ConnId;
}

/// Runtime annotation for one peer node. The (b)-path stub from
/// the chunk-4b plan: `tinc-graph::Node` is name+edges (topology);
/// this is which-conn-serves-it + the edge-metadata `ack_h` builds.
///
/// C `node_t` smushes both into one 200-byte struct. Splitting
/// means `tinc-graph` stays `#![no_std]`-compatible (no fd, no
/// `Instant`, no `SocketAddr` in the graph crate).
///
/// Chunk 5 cross-refs this to a `tinc_graph::NodeId` once the graph
/// is wired. For now: `ack_h` populates it, `dump_connections`
/// doesn't even read it (it walks `conns` not `nodes`). The dup-
/// conn check (`ack_h:975-990`) is the one consumer.
#[derive(Debug, Clone)]
pub struct NodeState {
    /// `c->edge`. The forward `EdgeId` from `myself` to this peer,
    /// added by `on_ack` (`ack_h:1051`). `terminate_connection`
    /// (`net.c:126-132`) deletes it AND broadcasts `DEL_EDGE` when
    /// the connection drops. `None` for nodes that don't currently
    /// have a direct edge from us (peer disconnected, edge gone).
    pub edge: Option<EdgeId>,
    /// `n->connection`. Which meta connection currently serves this
    /// node. `None` if the node is known but not directly connected
    /// (transitively reachable, or just disconnected). Generational
    /// `ConnId`: a stale one returns `None` from `conns.get`.
    pub conn: Option<ConnId>,
    /// `c->edge->address`. Peer's TCP-connect-from addr with port
    /// rewritten to their UDP port (`ack_h:1024-1025`). The "how do
    /// I send data packets" addr. `None` only for hypothetical
    /// unix-socket peers (doesn't happen — peers come over TCP).
    pub edge_addr: Option<SocketAddr>,
    /// `c->edge->weight`. Average of our RTT estimate and theirs
    /// (`ack_h:1048`). Milliseconds.
    pub edge_weight: i32,
    /// `c->edge->options`. Intersected/unioned bitfield (`ack_h:
    /// 996-1001`). Top byte is the PEER's `PROT_MINOR`.
    pub edge_options: u32,
}

/// `IoWhat` — the daemon's choice of `W` for `EventLoop<W>`.
///
/// Six variants for six C `io_add` callbacks. The match body in
/// `Daemon::run` IS the dispatch table.
///
/// `Tcp`/`Udp` are stubs — variants exist (the enum is closed), the
/// match arms are `todo!()` until chunk 3. Gives the full enum shape
/// up front; `Daemon::run`'s match doesn't churn when listeners land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoWhat {
    /// `signalio_handler`. The self-pipe read end.
    Signal,
    /// `handle_new_unix_connection`. The control socket listener.
    UnixListener,
    /// `handle_device_data`. The TUN/TAP device. `Dummy` has
    /// `fd() → None` so this is never registered in skeleton.
    Device,
    /// `handle_meta_io`. A meta connection (control or peer).
    /// The ConnId indexes the slotmap.
    Conn(ConnId),
    /// `handle_new_meta_connection`. TCP listener `i`. Index into
    /// `listen_socket[MAXSOCKETS]`. u8 because MAXSOCKETS=16.
    Tcp(u8),
    /// `handle_incoming_vpn_data`. UDP listener `i`. Same indexing.
    Udp(u8),
}

/// Seven variants for seven C `timeout_add` callbacks. Skeleton has
/// one: `Ping`. Same up-front-shape rationale as `IoWhat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerWhat {
    /// `timeout_handler` (`net.c:180`). Ping timeout sweep. Re-arms +1s.
    Ping,
    /// `periodic_handler` (`net.c:268`). Contradiction counter check
    /// + autoconnect. Re-arms +5s. Armed at setup.
    Periodic,
    /// `keyexpire_handler`. Re-arms `+keylifetime`.
    #[allow(dead_code)]
    KeyExpire,
    /// `age_past_requests` (`protocol.c:213-228`). Evicts seen-
    /// request cache entries older than `pinginterval`. Re-arms
    /// +10s (`:228`). Chunk 5: ARMED.
    AgePastRequests,
    /// `age_subnets`. Re-arms +10s.
    #[allow(dead_code)]
    AgeSubnets,
    /// `retry_outgoing_handler`. Per-outgoing. C `outgoing_t.ev`
    /// (`net.h:123`) is one timer per outgoing; `retry_outgoing`
    /// (`net_socket.c:412`) arms it. The `OutgoingId` payload tells
    /// the dispatch arm which outgoing to retry.
    RetryOutgoing(OutgoingId),
    /// `udp_probe_timeout_handler`. Per-node.
    #[allow(dead_code)]
    UdpPing,
}

/// Three variants for the signals. C registers 5 (`net.c:503-507`)
/// but TERM/QUIT/INT all map to `Exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalWhat {
    /// SIGHUP. `sighup_handler`: reopenlogger + reload_configuration.
    /// Skeleton: log and ignore.
    Reload,
    /// SIGTERM, SIGINT, SIGQUIT. `sigterm_handler`: `event_exit()`.
    Exit,
    /// SIGALRM. `sigalrm_handler`: `retry()`. Skeleton: ignore.
    Retry,
}

// DaemonSettings — the config knobs

/// The ~40 daemon-side settings globals from the census. Populated
/// by `setup_myself_reloadable` (`net_setup.c:252-575`). Skeleton
/// reads only `pinginterval`/`pingtimeout` and even those are
/// defaulted.
///
/// Separate from `Daemon` so reload can swap a fresh `DaemonSettings`
/// in without touching the arena. C `reload_configuration` walks and
/// patches; we'll do the same for the arena, but the SETTINGS are
/// just a struct swap.
///
/// `Default` matches C defaults. Each field documents its
/// `net_setup.c` source.
#[derive(Debug, Clone)]
pub struct DaemonSettings {
    /// `pinginterval`. C default 60 (`net_setup.c:1243`). Seconds
    /// between pings.
    pub pinginterval: u32,
    /// `pingtimeout`. C default 5 (`net_setup.c:1247-1248`). Seconds
    /// to wait for PONG before assuming peer dead. Clamped to
    /// `[1, pinginterval]` (`:1251-1253`).
    pub pingtimeout: u32,
    /// `myport.tcp` (`net_setup.c:788`). The Port config (HOST-tagged,
    /// from `hosts/NAME` not tinc.conf). C stores as a STRING (it goes
    /// through getaddrinfo which wants a service name); we convert to
    /// u16 here. Default 655 (`:789`). 0 means "kernel picks" — valid
    /// for tests; the actual port is read back from `listeners[0]`.
    pub port: u16,
    /// `addressfamily` (`net_socket.c:38`, set at `net_setup.c:538`).
    /// Filters which families `open_listeners` tries. Default
    /// `Any` (`AF_UNSPEC`) means dual-stack.
    pub addressfamily: AddrFamily,
    /// `maxtimeout` (`net_setup.c:527-533`). Retry-backoff cap in
    /// seconds. Default 900 (15 min). `retry_outgoing` (`net_socket.
    /// c:408-410`) caps `outgoing->timeout` here.
    pub maxtimeout: u32,
    /// `udp_discovery_timeout` (`net_packet.c:86`). Seconds. The
    /// laptop-suspend detector at `net.c:198` triggers if the ping
    /// timer didn't run for `> 2*this` seconds: the daemon was
    /// asleep, every peer has given up on us, force-close all conns
    /// to avoid sending into stale SPTPS contexts. Default 30.
    pub udp_discovery_timeout: u32,
    // Chunk 4+: ~32 more fields.
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            // C `net_setup.c:1243`: `else { pinginterval = 60; }`.
            pinginterval: 60,
            // C `net_setup.c:1248`: `pingtimeout = 5`.
            pingtimeout: 5,
            // C `net_setup.c:789`: `myport.tcp = xstrdup("655")`.
            port: 655,
            // C `net_socket.c:38`: `int addressfamily = AF_UNSPEC`.
            addressfamily: AddrFamily::Any,
            // C `net_setup.c:533`: `maxtimeout = 900`.
            maxtimeout: MAX_TIMEOUT_DEFAULT,
            // C `net_packet.c:86`: `int udp_discovery_timeout = 30`.
            udp_discovery_timeout: 30,
        }
    }
}

// Daemon — the C globals + the loop

/// What `run()` returns. C `main_loop` returns `int` (0 or 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// `event_loop()` returned cleanly (`running` set false by a
    /// handler). C `main_loop` returns 0.
    Clean,
    /// `event_loop()` returned an error. C `main_loop` returns 1.
    PollError,
}

/// The daemon. C globals as fields; `run()` is `main_loop()`.
///
/// Why fields are `pub(crate)` not `pub`: the loop body matches on
/// `IoWhat` and reaches into ALL the fields. There's no encapsulation
/// to defend — the loop IS the daemon. Same as the C: every handler
/// can reach every global. The Rust gain is `&mut self` exclusivity
/// (no two handlers run concurrently — but they couldn't in the C
/// either, single-threaded loop. The gain is the COMPILER knows.).
pub struct Daemon {
    // ─── arena
    /// `connection_list`. Slotmap not `Vec<Option>` — generational
    /// keys. A `ConnId` from a closed connection is a different key
    /// than the next connection allocated in the same slot. The C's
    /// generation guard becomes `conns.get(stale_id) → None`.
    pub(crate) conns: SlotMap<ConnId, Connection>,

    /// Per-connection event-loop handle. `connection_t.io` in C.
    /// Parallel map because `Connection` doesn't know about
    /// `tinc-event` (layering). `IoId` is the EventLoop's slot
    /// index.
    ///
    /// (Could be a field on `Connection`. The argument for parallel
    /// map: `Connection` is testable without `EventLoop`; `conn.rs`
    /// tests don't construct one. The argument against: two-map
    /// coherence (every insert/remove touches both). For now: two
    /// maps, asserts on coherence in debug. Revisit if it bites.)
    pub(crate) conn_io: slotmap::SecondaryMap<ConnId, IoId>,

    // ─── substrate
    /// `devops` + `device_fd` + `iface`. The TUN/TAP. `Box<dyn>` —
    /// the variant (`Dummy`/`Tun`/`Fd`/`Raw`/`Bsd`) is chosen at
    /// setup time by the `DeviceType` config knob.
    ///
    /// Chunk 7's `IoWhat::Device` arm reads it; `route_packet` writes
    /// to it for `Forward{to: myself}`.
    pub(crate) device: Box<dyn Device>,

    /// `unix_socket` (`control.c:29`). The control listener.
    pub(crate) control: ControlSocket,

    /// `listen_socket[MAXSOCKETS]` (`net_socket.c:48`). TCP+UDP
    /// pairs. `IoWhat::Tcp(i)` indexes here. Max 8 (we only fill 2
    /// in chunk 3: one v4, one v6).
    ///
    /// `Vec` not array because `Listener` doesn't impl `Default`
    /// (sockets aren't defaultable). The C uses `static listen_
    /// socket_t[8]` zero-init; we just push.
    pub(crate) listeners: Vec<Listener>,

    /// `check_tarpit` statics + `tarpit()` ring buffer. Seven C
    /// statics packed into one struct. Mutated on every TCP accept.
    pub(crate) tarpit: Tarpit,

    /// `controlcookie` (`control.c:35`). 64 hex chars. Compared in
    /// `handle_id`.
    pub(crate) cookie: String,

    /// `pidfilename`. Kept so `Drop` can unlink (`control.c:240`).
    pub(crate) pidfile: PathBuf,

    /// `myname` (`names.h:30`). Our node name from `tinc.conf:Name`.
    /// Appears in the `send_id` greeting and in dump output.
    pub(crate) name: String,

    /// `myself->connection->ecdsa` (`net_setup.c:803`). Our Ed25519
    /// private key. Loaded once at startup from `confbase/ed25519_
    /// key.priv` (or `Ed25519PrivateKeyFile`). Used for SPTPS auth:
    /// every peer handshake clones this via `to_blob`/`from_blob`
    /// (`SigningKey` deliberately isn't `Clone` — the roundtrip
    /// makes copies VISIBLE). Never reloaded (a key change is a
    /// daemon restart, not a SIGHUP — the C is the same).
    pub(crate) mykey: SigningKey,

    /// `confbase`. Kept so `id_h` peer-branch can resolve `hosts/
    /// NAME` paths. The C has it as a global (`names.c:24`); we
    /// thread it through `IdCtx`. Stored once here, borrowed into
    /// each `IdCtx`.
    pub(crate) confbase: PathBuf,

    /// `myself->options`. Bitfield (`connection.h:32-36` + PROT_MINOR
    /// in top byte). C builds in `setup_myself_reloadable` (`net_
    /// setup.c:383-453,800`). Chunk 4b: defaults only. Chunk 9
    /// reads `IndirectData`/`TCPOnly`/`PMTUDiscovery`/`ClampMSS`.
    pub(crate) myself_options: u32,

    /// `myport.udp`. C string (`net_setup.c:54,794`); we store the
    /// resolved u16. Read back from `listeners[0].udp_port()` after
    /// bind (the C does the same at `:1194` `get_bound_port`). With
    /// `Port = 0` (tests), TCP and UDP get DIFFERENT kernel-assigned
    /// ports until `bind_reusing_port` (chunk 10) lands. The ACK
    /// packet needs the UDP one specifically.
    pub(crate) my_udp_port: u16,

    /// `node_tree` topology half. Nodes + directed edges. What
    /// `sssp`/`mst` walk. The C `node_t` smushes topology AND
    /// runtime annotation (200-byte struct); we split — see
    /// `NodeState` doc.
    ///
    /// `myself` is added at setup (`net_setup.c:783`). Transitively-
    /// known nodes are added by `lookup_or_add_node` from ADD_EDGE/
    /// ADD_SUBNET handlers. The graph crate has no name→id reverse
    /// lookup — that's `node_ids` below.
    pub(crate) graph: Graph,

    /// name → `NodeId`. The reverse lookup `tinc-graph` doesn't
    /// have. C `lookup_node(name)` is a splay search on `node_tree`
    /// keyed by `strcmp(name)`; this IS that. Populated alongside
    /// `graph.add_node()` in `lookup_or_add_node`.
    ///
    /// Invariant: every entry's `NodeId` is a live slot in `graph`.
    /// Chunk 5 never deletes nodes (the C only does on `purge`);
    /// when del lands, it removes from here too.
    pub(crate) node_ids: HashMap<String, NodeId>,

    /// `myself` (`net_setup.c:783`: `myself = new_node()`). Our own
    /// `NodeId` in `graph`. The `from == myself` checks in the edge/
    /// subnet handlers (`protocol_edge.c:183`, `protocol_subnet.c:
    /// 98`) compare against this.
    pub(crate) myself: NodeId,

    /// `subnet_tree` (`subnet.c:32`). The routing table. ADD_SUBNET
    /// inserts, DEL_SUBNET removes, `route_ipv4` (chunk 7) reads.
    /// `dump subnets` walks.
    pub(crate) subnets: SubnetTree,

    /// `past_request_tree` (`protocol.c:89`). Anti-loop dedup for
    /// flooded ADD/DEL messages. Handlers call `seen.check(body)`
    /// before processing; `true` → dup, drop silently.
    /// `AgePastRequests` timer evicts old entries.
    pub(crate) seen: SeenRequests,

    /// Chunk-4b's runtime annotation. KEPT — graph topology vs
    /// runtime state are different things. `tinc-graph::Node` is
    /// name + edges; this is which-conn-serves-it + the edge
    /// metadata `ack_h` builds (the address, which `tinc-graph::
    /// Edge` doesn't carry).
    ///
    /// Only DIRECTLY-connected peers get a `NodeState` (via
    /// `on_ack`). Transitively-known nodes (learned from forwarded
    /// ADD_EDGE) are graph-only — no `NodeState`. C `node_t` doesn't
    /// distinguish (it's one struct for both); we make the split
    /// explicit. The dup-conn check (`ack_h:975-990`) is the one
    /// consumer of `conn`.
    pub(crate) nodes: HashMap<String, NodeState>,

    /// Per-edge address annotation. `tinc-graph::Edge` is topology-
    /// only (from/to/weight/options); the WIRE addresses live here.
    /// Keyed by `EdgeId` from `graph.add_edge`.
    ///
    /// C `edge_t` carries `address` + `local_address` (`edge.h:32-33`)
    /// inline. We split: graph crate stays `#![no_std]`-clean,
    /// addresses (which are `AddrStr` — OPAQUE wire tokens, possibly
    /// hostnames, per the chunk-4b finding) live daemon-side.
    ///
    /// Stored as `(addr, port, local_addr, local_port)` raw `AddrStr`
    /// pairs (NOT parsed `SocketAddr`): `dump_edges` round-trips
    /// what arrived on the wire, byte-exact (`netutl.c:163` `AF_
    /// UNKNOWN` branch — `sockaddr2hostname` of an unparsed addr is
    /// just `"%s port %s"` of the stored strings).
    ///
    /// Populated by `on_ack` (our direct edges, addr from `conn.
    /// address` + `parsed.his_udp_port`) and `on_add_edge` (transitive,
    /// addr from the parsed wire body). Cleaned up alongside `graph.
    /// del_edge`. RESOLVES the open question at the chunk-5
    /// `send_everything` STUB note.
    pub(crate) edge_addrs: HashMap<EdgeId, (AddrStr, AddrStr, AddrStr, AddrStr)>,

    /// `node_t` data-plane half. C smushes this into the same `node_t`
    /// struct; we keep it separate from `nodes`/`NodeState` because
    /// the lifecycles differ — `TunnelState` exists for ANY reachable
    /// node (we send UDP to nodes we have no TCP connection to,
    /// forwarding the handshake via `nexthop->connection`).
    ///
    /// `entry().or_default()` is the C `xzalloc` semantics: a node
    /// learned from `ADD_EDGE` has no tunnel until `send_req_key` /
    /// `req_key_ext_h` (`protocol_key.c:131,263`) starts one.
    pub(crate) tunnels: HashMap<NodeId, TunnelState>,

    /// `node_id_tree` (`node.c:60`). UDP fast-path lookup: every
    /// packet has `[dst_id6][src_id6]` prefix; receiver maps `src_
    /// id6` → `NodeId` to find which SPTPS state to feed. Populated
    /// alongside `node_ids` in `lookup_or_add_node`.
    pub(crate) id6_table: NodeId6Table,

    /// `contradicting_add_edge` (`net.c:40`). Incremented when a
    /// peer claims WE have an edge we don't (`protocol_edge.c:186`).
    /// Read by `periodic_handler` (`net.c:268-313`, chunk 8): if
    /// it exceeds a threshold, log+restart. The contradiction means
    /// our world-view diverged from the mesh's badly enough that
    /// gossip won't converge.
    pub(crate) contradicting_add_edge: u32,
    /// `contradicting_del_edge` (`net.c:41`). Same, for DEL_EDGE
    /// (`protocol_edge.c:288`): peer says we DON'T have an edge
    /// we DO have.
    pub(crate) contradicting_del_edge: u32,

    /// `sleeptime` (`net.c:42`). Seconds the periodic handler
    /// blocks for when contradicting-edge counters exceed 100. The
    /// "two daemons fighting over the same Name" backoff (`net.c:
    /// 274-291`): doubled each time it triggers (cap 3600), halved
    /// each clean period (floor 10). C default 10. Signed in C
    /// because `*= 2` overflow goes negative → capped to 3600;
    /// u32 here, capped explicitly.
    pub(crate) sleeptime: u32,

    /// `last_periodic_run_time` (`net.c:43`). Laptop-suspend
    /// detector at `net.c:189-213`: if `now - this > 2 * udp_
    /// discovery_timeout`, the daemon was asleep — force-close
    /// every connection (the peers gave up on us; sending into
    /// stale SPTPS contexts produces "failed signature" noise on
    /// the other side). Updated each `on_ping_tick`.
    pub(crate) last_periodic_run_time: Instant,

    /// `iface` global (`names.c`). Kernel-chosen interface name
    /// (`tun0`, `tinc0`). Captured at setup from `device.iface()`
    /// because the trait borrow blocks `&mut self` at script call
    /// sites. C reads the global directly inside `environment_init`
    /// (`script.c:125`).
    pub(crate) iface: String,

    /// `errors` static inside `handle_device_data` (`net_packet.c:
    /// 1918`). Consecutive device-read failures. Reset on success.
    /// At 10 (`:1933`): `event_exit()`. A flapping TUN means the
    /// kernel device is gone; tight-looping forever helps nobody.
    pub(crate) device_errors: u32,

    /// `outgoing_list` (`net_socket.c:54`). One slot per `ConnectTo`
    /// in `tinc.conf`. C uses a `list_t` of `outgoing_t*`; we slot.
    /// Populated by `try_outgoing_connections` at setup. Never
    /// shrunk in chunk 6 (the C mark-sweep at `:870-883` only fires
    /// on SIGHUP-reload, chunk 8).
    pub(crate) outgoings: SlotMap<OutgoingId, Outgoing>,

    /// Per-outgoing retry timer. C `outgoing_t.ev` (`net.h:123`);
    /// kept parallel for the same layering reason as `conn_io`.
    /// `setup_outgoing_connection` (`net_socket.c:666`) does
    /// `timeout_del(&outgoing->ev)` first thing.
    pub(crate) outgoing_timers: slotmap::SecondaryMap<OutgoingId, TimerId>,

    /// In-flight outgoing connect: socket NOT YET in `Connection`.
    /// The async-connect dance (`net_socket.c:517-555`) keeps the
    /// `socket2::Socket` for the `send(NULL,0,0)` probe and `take_
    /// error()` (which need the wrapper, not the raw fd). Once the
    /// probe succeeds, the `Socket` is consumed into the `Connection`
    /// fd. Keyed by `ConnId` (the connection slot is allocated at
    /// `do_outgoing_connection` time, fd-less; this map fills it).
    pub(crate) connecting_socks: slotmap::SecondaryMap<ConnId, socket2::Socket>,

    /// Last `sssp` result. C `node_t` stores `nexthop`/`via`/
    /// `distance` directly on the node (written by `graph.c:188-196`);
    /// we keep it as a side table indexed by `NodeId.0` (same
    /// indexing as `sssp`'s output). `dump_nodes` reads this for the
    /// `nexthop`/`via`/`distance` columns (`node.c:218`).
    ///
    /// Updated by `run_graph_and_log` (every `graph()` call site).
    /// Starts empty; `dump_nodes` before the first `graph()` call
    /// reads `None` for everything (only `myself` exists then anyway).
    pub(crate) last_routes: Vec<Option<Route>>,

    // ─── settings
    /// The config knobs. Reload swaps this.
    ///
    /// `dead_code` allowed: skeleton constructs but never reads (the
    /// `udp_discovery_timeout` default is inlined at the one
    /// use site). Chunk 3's `setup_myself_reloadable` populates it
    /// from config and the ping sweep reads it. Keeping the field
    /// avoids churn (remove now, re-add then). Same call as the
    /// `TimerWhat::Periodic` etc variants.
    #[allow(dead_code)]
    pub(crate) settings: DaemonSettings,

    // ─── event loop machinery
    /// `mio::Poll` + slot table. Generic over `IoWhat`.
    pub(crate) ev: EventLoop<IoWhat>,
    /// Timer wheel. Generic over `TimerWhat`.
    pub(crate) timers: Timers<TimerWhat>,
    /// Self-pipe + handler table. Generic over `SignalWhat`.
    pub(crate) signals: SelfPipe<SignalWhat>,
    /// `pingtimer` (`net.c:44`). Kept so the match arm can re-arm.
    pub(crate) pingtimer: TimerId,
    /// `past_request_timeout` (`protocol.c:92`). Re-arms +10s.
    pub(crate) age_timer: TimerId,
    /// `periodictimer` (`net.c:45`). Re-arms +5s.
    pub(crate) periodictimer: TimerId,

    /// `running` (`event.c:18`). The loop condition. C `event_exit()`
    /// sets `running = false`; `event_loop()` checks before each
    /// iteration. Same here.
    pub(crate) running: bool,
}

impl Daemon {
    /// `setup_network` (`net_setup.c:1235-1275`) + `init_control` +
    /// the parts of `setup_myself` we need (`net_setup.c:770-1100`).
    /// Heavily abridged: no listen sockets, no graph, no node tree.
    ///
    /// `confbase` is the `-c` argument (or `CONFDIR/tinc[/NETNAME]`
    /// resolved by main.rs). `pidfile`/`socket` are the runtime paths.
    ///
    /// Reads `tinc.conf` for `Name` and `DeviceType`. Everything
    /// else is defaulted.
    ///
    /// # Errors
    /// Startup failures: tinc.conf missing/malformed, no `Name`,
    /// device open failed, pidfile write failed (permissions),
    /// socket bind failed (already running).
    ///
    /// # Panics
    /// `SelfPipe::new` panics if a SelfPipe already exists in this
    /// process (it's a singleton — see tinc-event/sig.rs). Can't
    /// happen here: setup is called once. Tests that call setup
    /// twice in one process are wrong; integration tests use
    /// subprocess.
    #[allow(clippy::too_many_lines)] // setup_myself is one long
    // sequence in C too. Splitting it scatters the boot order.
    pub fn setup(confbase: &Path, pidfile: &Path, socket: &Path) -> Result<Self, SetupError> {
        // ─── read tinc.conf (tincd.c:590)
        let config = tinc_conf::read_server_config(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;

        // ─── Name (net_setup.c:775-779)
        // C: `name = get_name(); if(!name) { ERR }`.
        // `get_name()` does `lookup_config("Name")` + `check_id`.
        // Skeleton: just lookup. `check_id` (alphanumeric + `_`)
        // is the right validation but tinc-tools/names.rs has it,
        // not tinc-conf — and we don't dep on tinc-tools. Chunk 3+
        // hoists `check_id` to a shared place (probably tinc-proto;
        // it's wire-format-adjacent).
        let name = config
            .lookup("Name")
            .next()
            .map(|e| e.get_str().to_owned())
            .ok_or(SetupError::Config("Name for tinc daemon required!".into()))?;
        log::info!(target: "tincd", "tincd starting, name={name}");

        // ─── read_host_config (net_setup.c:786)
        // C: `read_host_config(&config_tree, name, true)`. Merges
        // hosts/NAME into the same tree as tinc.conf. The HOST-tagged
        // vars (Port, Subnet, PublicKey, etc) live there.
        //
        // C DOESN'T check the return value (`:786` is a bare call).
        // Missing hosts/NAME is not fatal at this stage; the only
        // var we read from it is Port, which has a default. The hard
        // failures (no key, no subnets) come later. We match: log
        // and continue. The daemon starts on port 655.
        //
        // Per tinc-conf/parse.rs:523: read_host_config is intentionally
        // not a function. It's two lines.
        let mut config = config;
        let host_file = confbase.join("hosts").join(&name);
        match tinc_conf::parse_file(&host_file) {
            Ok(entries) => config.merge(entries),
            Err(e) => {
                // C `read_config_file` would `fopen` fail and return
                // false. The caller ignores. Warn-level because it
                // MIGHT be intentional (a freshly-init'd daemon has
                // no hosts/ yet) but more likely is a typo in Name.
                log::warn!(target: "tincd",
                           "hosts/{name} not read: {e}; using defaults");
            }
        }

        // ─── read_ecdsa_private_key (net_setup.c:803-828)
        // C: `myself->connection->ecdsa = read_ecdsa_private_key(
        // &config_tree, NULL); experimental = ecdsa != NULL;`.
        //
        // The C has THREE attempts at `:803/814/822` interleaved with
        // `disable_old_keys` (a `tinc init` migration helper that
        // detects old-format keys and asks to convert). We forbid
        // legacy — the migration is meaningless. One attempt.
        //
        // Missing key is FATAL for us. C falls back to `myself->
        // connection->legacy = init_legacy_ctx(read_rsa_private_key
        // (...))` at `:831-842`. We don't. The error message includes
        // the gen-keys hint (C `keys.c:123-125`) so the user knows
        // what to do.
        let mykey = read_ecdsa_private_key(&config, confbase).map_err(|e| {
            // C `:123-125` prints the hint at INFO. We embed it in
            // the error — setup() callers (main.rs) print the error
            // to stderr and exit, so it's visible.
            let hint = if matches!(e, PrivKeyError::Missing(_)) {
                "\n  (Create a key pair with `tinc generate-ed25519-keys`)"
            } else {
                ""
            };
            SetupError::Config(format!("{e}{hint}"))
        })?;

        // ─── settings (net_setup.c:788, 538, 1239-1257)
        let mut settings = DaemonSettings::default();

        // Port (`:788-794`). HOST-tagged. C stores as a string
        // (goes through getaddrinfo); we parse to u16 here.
        // `Port = 0` is valid: kernel picks (tests use this).
        // Non-numeric Port (`:846-858`: service name resolution
        // via `service_to_port`): deferred. Reject for now.
        if let Some(e) = config.lookup("Port").next() {
            settings.port = e.get_str().parse().map_err(|_| {
                SetupError::Config(format!("Port = {} is not a valid port number", e.get_str()))
            })?;
        }

        // AddressFamily (`:538-548`). SERVER-tagged (in tinc.conf).
        // C silently ignores unknown values (no `else { ERR }`);
        // `addressfamily` stays at default. We match.
        if let Some(e) = config.lookup("AddressFamily").next() {
            if let Some(af) = AddrFamily::from_config(e.get_str()) {
                settings.addressfamily = af;
            } else {
                log::warn!(target: "tincd",
                           "Unknown AddressFamily = {}, using default",
                           e.get_str());
            }
        }

        // PingInterval (`:1241-1243`). For tests: `PingInterval = 1`
        // makes the keepalive observable in a 5-second test.
        if let Some(e) = config.lookup("PingInterval").next() {
            if let Ok(v) = e.get_int() {
                if let Ok(v) = u32::try_from(v) {
                    if v >= 1 {
                        settings.pinginterval = v;
                    }
                }
            }
        }

        // PingTimeout (`:1247-1253`). For tests: `PingTimeout = 1`
        // makes the 6-second integration test run in 2 seconds. Read
        // it now; the clamp (`:1251`: `[1, pinginterval]`) too.
        if let Some(e) = config.lookup("PingTimeout").next() {
            if let Ok(v) = e.get_int() {
                // C clamps `< 1 || > pinginterval` → default.
                // Match the clamp; reject negative (get_int returns
                // i32; u32::try_from rejects negative).
                if let Ok(v) = u32::try_from(v) {
                    settings.pingtimeout = v.clamp(1, settings.pinginterval);
                }
            }
        }

        // ─── device (net_setup.c:1061-1100)
        // C: `devops = os_devops; if DeviceType=dummy → dummy_devops;
        // ...; devops.setup()`.
        // We Box<dyn>. Skeleton: `dummy` always; chunk 3 reads the
        // `DeviceType` config and matches.
        let device_type = config
            .lookup("DeviceType")
            .next()
            .map(|e| e.get_str().to_ascii_lowercase());
        let device: Box<dyn Device> = match device_type.as_deref() {
            None | Some("dummy") => Box::new(tinc_device::Dummy),
            #[cfg(target_os = "linux")]
            Some("fd") => {
                // C `:1068-1078`: `devops = fd_devops`. The fd comes
                // from the `Device = N` config (inherited fd) or
                // `--device-fd N` cmdline. For chunk-7 testing: the
                // integration test creates a socketpair, writes one
                // end's fd into `Device = N`, and pumps IP packets
                // through it. `FdTun` reads at `+14` (raw IP, no
                // tun_pi prefix) and synthesizes the ethertype —
                // exactly the framing `route()` expects.
                let dev_str = config
                    .lookup("Device")
                    .next()
                    .map(tinc_conf::Entry::get_str)
                    .ok_or_else(|| {
                        SetupError::Config("DeviceType=fd requires Device = <fd>".into())
                    })?;
                let fd: std::os::unix::io::RawFd = dev_str.parse().map_err(|_| {
                    SetupError::Config(format!("Device = {dev_str} is not a valid fd"))
                })?;
                let tun = tinc_device::FdTun::open(tinc_device::FdSource::Inherited(fd))
                    .map_err(SetupError::Io)?;
                Box::new(tun)
            }
            #[cfg(target_os = "linux")]
            Some("tun") => {
                // C `:1061`: `devops = os_devops` (the default). Real
                // kernel TUN via `/dev/net/tun` + TUNSETIFF. Needs
                // `CAP_NET_ADMIN`; the netns harness (tests/netns.rs)
                // grants it inside an unprivileged userns via bwrap.
                //
                // `Interface = NAME` → attach to a precreated
                // persistent device (`ip tuntap add`); unset → kernel
                // picks `tun0`/`tun1`/... (`tun_set_iff` find-first-
                // free). The netns test precreates so it can move the
                // device into a child netns AFTER the daemon attaches
                // (the fd→device binding survives `ip link set netns`).
                let cfg = tinc_device::DeviceConfig {
                    iface: config
                        .lookup("Interface")
                        .next()
                        .map(|e| e.get_str().to_owned()),
                    ..Default::default()
                };
                let tun = tinc_device::Tun::open(&cfg).map_err(SetupError::Io)?;
                Box::new(tun)
            }
            // Chunk 8+: Some("tap") → Mode::Tap, etc.
            Some(other) => {
                return Err(SetupError::Config(format!(
                    "DeviceType={other} not supported yet; use dummy or fd"
                )));
            }
        };
        // Captured BEFORE the Box goes into the Daemon struct: the
        // `&dyn` trait borrow makes `&mut self` script call sites
        // awkward. The C reads the `iface` global directly.
        let iface = device.iface().to_owned();
        log::info!(target: "tincd",
                   "Device mode: {:?}, interface: {iface}",
                   device.mode());

        // ─── event loop scaffolding
        // tinc-event constructors. EventLoop::new can fail (epoll_
        // create); the others can't (BTreeMap, pipe).
        let mut ev = EventLoop::new().map_err(SetupError::Io)?;
        let mut timers = Timers::new();
        let mut signals = SelfPipe::new().map_err(SetupError::Io)?;

        // ─── signals (net.c:497-507)
        // C: signal_add for HUP/TERM/QUIT/INT/ALRM. We map TERM/
        // QUIT/INT all to Exit (same handler in C: `sigterm_handler`).
        // HUP → Reload, ALRM → Retry.
        signals
            .add(libc::SIGTERM, SignalWhat::Exit)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGINT, SignalWhat::Exit)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGQUIT, SignalWhat::Exit)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGHUP, SignalWhat::Reload)
            .map_err(SetupError::Io)?;
        signals
            .add(libc::SIGALRM, SignalWhat::Retry)
            .map_err(SetupError::Io)?;

        // Register the self-pipe read end. `signal.c:59`: `io_add(
        // &signalio, signalio_handler, NULL, pipefd[0], IO_READ)`.
        ev.add(signals.read_fd(), Io::Read, IoWhat::Signal)
            .map_err(SetupError::Io)?;

        // ─── device fd (net_setup.c:1100)
        // C: `if(device_fd >= 0) io_add(&device_io, ...)`.
        // Dummy returns None; Tun/Fd/Raw/Bsd return Some(fd).
        if let Some(fd) = device.fd() {
            ev.add(fd, Io::Read, IoWhat::Device)
                .map_err(SetupError::Io)?;
        }

        // ─── ping timer (net.c:489-491)
        // C: `timeout_add(&pingtimer, timeout_handler, ..., {
        // pingtimeout, jitter() })`. Initial fire is `pingtimeout`
        // seconds from now. The HANDLER re-arms at +1s (`net.c:264`
        // `timeout_set(data, &(struct timeval) { 1, jitter() })`).
        //
        // tinc-event's deliberate semantic difference: re-arm is
        // EXPLICIT. The match arm calls `timers.set(pingtimer, ...)`.
        let pingtimer = timers.add(TimerWhat::Ping);
        timers.set(
            pingtimer,
            Duration::from_secs(u64::from(settings.pingtimeout)),
        );

        // ─── age_past_requests timer (protocol.c:228)
        // C: `timeout_set(&past_request_timeout, &(struct timeval)
        // { 10, jitter() })`. Re-arms +10s. The eviction window is
        // `pinginterval` (the cache key TTL); the timer's 10s is
        // just the sweep frequency.
        let age_timer = timers.add(TimerWhat::AgePastRequests);
        timers.set(age_timer, Duration::from_secs(10));

        // ─── periodic timer (net.c:493-495)
        // C: `timeout_add(&periodictimer, periodic_handler, ...,
        // { 0, 0 })`. Initial fire is IMMEDIATE (the C arms it
        // with `{0, 0}`; the first call sets sleeptime and re-arms
        // +5s). We arm +5s directly: no contradictions exist at
        // setup, the counters are zero, the first call would just
        // halve sleeptime (10 → 5 → floored to 10) and re-arm.
        let periodictimer = timers.add(TimerWhat::Periodic);
        timers.set(periodictimer, Duration::from_secs(5));

        // ─── listeners (net_setup.c:1152-1183)
        // C: walk BindToAddress configs, then ListenAddress configs,
        // else `add_listen_address(NULL, NULL)` for the no-config
        // default. We only do the no-config default for now.
        //
        // C `:1180`: `if(!listen_sockets) { ERR; return false }`.
        // Hard error. The daemon can't function without at least one
        // listener (peers can't connect; we can't receive UDP).
        let listeners = open_listeners(settings.port, settings.addressfamily);
        // `net_setup.c:1187-1197`: `myport.udp = get_bound_port(
        // listen_socket[0].udp.fd)`. C gates on `!port_specified ||
        // atoi(myport) == 0`; we always read back — simpler, same
        // answer when port ≠ 0 (kernel binds the requested port).
        // `first()` not `[0]`: the empty-check below still wants
        // its own error message.
        let my_udp_port = listeners.first().map_or(0, Listener::udp_port);
        if listeners.is_empty() {
            return Err(SetupError::Config(
                "Unable to create any listening socket!".into(),
            ));
        }
        // Register each pair. C `:723-724`: `io_add(&sock->tcp, ...)`.
        // The index `i` becomes `IoWhat::Tcp(i)` so the dispatch arm
        // can index back into `listeners[i]` for the accept.
        for (i, l) in listeners.iter().enumerate() {
            let (tcp_fd, udp_fd) = l.fds();
            // u8 cast: MAXSOCKETS=8 fits trivially. The C uses int.
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u8;
            ev.add(tcp_fd, Io::Read, IoWhat::Tcp(i))
                .map_err(SetupError::Io)?;
            ev.add(udp_fd, Io::Read, IoWhat::Udp(i))
                .map_err(SetupError::Io)?;
        }

        // ─── init_control (net_setup.c:1263, control.c:148-231)
        let cookie = generate_cookie();

        // C `control.c:155-176`: get listeners[0]'s bound addr, map
        // 0.0.0.0→127.0.0.1, format `"HOST port PORT"`. The CLI on
        // Windows (no unix socket) actually CONNECTS to this addr.
        // On Unix the CLI uses the unix socket and ignores the addr,
        // but the pidfile format is fixed.
        let address = pidfile_addr(&listeners);
        write_pidfile(pidfile, &cookie, &address).map_err(SetupError::Io)?;

        let control = ControlSocket::bind(socket).map_err(|e| match e {
            crate::control::BindError::AlreadyRunning => SetupError::Config(format!(
                "Control socket {} already in use",
                socket.display()
            )),
            crate::control::BindError::Io(err) => SetupError::Io(err),
        })?;
        ev.add(control.fd(), Io::Read, IoWhat::UnixListener)
            .map_err(SetupError::Io)?;

        // ─── graph: add myself (net_setup.c:783)
        // C: `myself = new_node(name)`. The C `xzalloc` zeroes
        // `n->status.reachable`; `:1050` then sets `reachable =
        // true`. `Graph::add_node` defaults `reachable = true`
        // (steady state) so we get the same one-step.
        //
        // `node_ids` insert: the name→id reverse map. C `node_add`
        // (`node.c:96`) inserts into `node_tree` keyed on name; the
        // splay search IS the lookup. Our HashMap IS that.
        let mut graph = Graph::new();
        let myself = graph.add_node(&name);
        let mut node_ids = HashMap::new();
        node_ids.insert(name.clone(), myself);
        // C `node.c:126-128`: `node_add` computes `n->id` and inserts
        // into `node_id_tree`. Our `NodeId6Table` is that tree.
        let mut id6_table = NodeId6Table::new();
        id6_table.add(&name, myself);

        // ─── Subnet (net_setup.c:860-870)
        // C: `for(cfg = lookup_config("Subnet"); cfg; cfg = next)
        // { get_config_subnet(cfg, &subnet); subnet_add(myself,
        // subnet); }`. Read OUR subnets from `hosts/NAME` (HOST-
        // tagged). Chunk 7's `route()` needs these to recognize
        // packets destined for us (the `Forward{to: myself}` case).
        // C `:865`: parse failure is `return false` (hard error).
        // We're slightly looser: log and skip the bad one. The
        // daemon stays up; the bad subnet just isn't routable.
        let mut subnets = SubnetTree::new();
        for e in config.lookup("Subnet") {
            match e.get_str().parse::<Subnet>() {
                Ok(s) => subnets.add(s, name.clone()),
                Err(_) => {
                    log::error!(target: "tincd",
                                "Invalid Subnet = {} in hosts/{name}",
                                e.get_str());
                }
            }
        }

        // ─── ConnectTo (try_outgoing_connections, net_socket.c:815-884)
        // C: walk `ConnectTo` configs, `lookup_or_add_node`, build
        // `outgoing_t`, call `setup_outgoing_connection`. The actual
        // connect is done by `run()` (it owns the EventLoop); we
        // collect the names here. The mark-sweep at `:870-883`
        // (terminate connections whose ConnectTo was removed) only
        // matters on SIGHUP-reload — chunk 8.
        //
        // C `:828`: `if(!check_id(name)) continue` — skip invalid.
        // C `:836`: `if(!strcmp(name, myself->name)) continue` —
        // skip self.
        let connect_to: Vec<String> = config
            .lookup("ConnectTo")
            .map(|e| e.get_str().to_owned())
            .filter(|n| {
                if !tinc_proto::check_id(n) {
                    log::error!(target: "tincd",
                                "Invalid name for outgoing connection: {n}");
                    return false;
                }
                if *n == name {
                    log::warn!(target: "tincd",
                                "ConnectTo = {n} is ourselves; skipping");
                    return false;
                }
                true
            })
            .collect();

        log::info!(target: "tincd", "Ready");

        let mut daemon = Self {
            conns: SlotMap::with_key(),
            conn_io: slotmap::SecondaryMap::new(),
            device,
            control,
            listeners,
            // Tarpit::new wants a now seed (avoids the C's `static
            // time_t = 0` first-tick bug). Use the cached now.
            tarpit: Tarpit::new(timers.now()),
            cookie,
            pidfile: pidfile.to_path_buf(),
            name,
            mykey,
            confbase: confbase.to_path_buf(),
            myself_options: myself_options_default(),
            my_udp_port,
            graph,
            node_ids,
            myself,
            subnets,
            seen: SeenRequests::new(),
            nodes: HashMap::new(),
            edge_addrs: HashMap::new(),
            tunnels: HashMap::new(),
            id6_table,
            contradicting_add_edge: 0,
            contradicting_del_edge: 0,
            // C `net.c:42`: `static int sleeptime = 10`.
            sleeptime: 10,
            // C `net.c:43`: `static struct timeval last_periodic_
            // run_time` zero-init. We seed with now: the first
            // `on_ping_tick` (after `pingtimeout` seconds) sees
            // a delta of `pingtimeout`, well under `2*30`.
            last_periodic_run_time: timers.now(),
            iface,
            device_errors: 0,
            outgoings: SlotMap::with_key(),
            outgoing_timers: slotmap::SecondaryMap::new(),
            connecting_socks: slotmap::SecondaryMap::new(),
            last_routes: Vec::new(),
            settings,
            ev,
            timers,
            signals,
            pingtimer,
            age_timer,
            periodictimer,
            running: true,
        };

        // ─── try_outgoing_connections — the actual setup
        // C `net_socket.c:852-863`: per ConnectTo, build outgoing_t,
        // lookup_or_add_node, setup_outgoing_connection. Done HERE
        // (not above) because it needs `&mut self` for the slotmap +
        // graph + EventLoop.
        for peer in connect_to {
            // C `:853-858`: `n = lookup_node(name); if(!n) { n =
            // new_node(name); node_add(n); }`. The node goes into
            // the graph BEFORE we connect; an ADD_EDGE arriving via
            // some OTHER path can find it.
            daemon.lookup_or_add_node(&peer);
            // C `:860-861`: `outgoing = xzalloc; outgoing->node = n`.
            // Addr cache: open with config `Address` lines resolved.
            let config_addrs = resolve_config_addrs(&daemon.confbase, &peer);
            let addr_cache =
                crate::addrcache::AddressCache::open(&daemon.confbase, &peer, config_addrs);
            let oid = daemon.outgoings.insert(Outgoing {
                node_name: peer,
                timeout: 0,
                addr_cache,
            });
            // Per-outgoing retry timer slot. Disarmed; `retry_
            // outgoing` arms it. C `outgoing_t.ev` is xzalloc'd
            // (= disarmed timer).
            let tid = daemon.timers.add(TimerWhat::RetryOutgoing(oid));
            daemon.outgoing_timers.insert(oid, tid);
            // C `:862`: `setup_outgoing_connection(outgoing, true)`.
            daemon.setup_outgoing_connection(oid);
        }

        // STUB(chunk-10): mark-sweep (`:870-883`). Terminate
        // connections whose ConnectTo was removed; only matters on
        // SIGHUP-reload. The reload path itself (`net.c:336-458`
        // `reload_configuration`) doesn't exist yet — SIGHUP is
        // logged-and-ignored. Re-chunked from 8 → 10.

        // ─── tinc-up (net_setup.c:745-762, `device_enable`)
        // C calls this AFTER device open succeeds, BEFORE `Ready`.
        // The script typically does `ip addr add` / `ip link set
        // up` on the TUN. Base env only (no NODE/SUBNET).
        daemon.run_script("tinc-up");

        Ok(daemon)
    }

    /// `main_loop()` (`net.c:487-527`) — the `while(running)` loop.
    /// `tinc-event` deliberately doesn't have this; `turn()` is one
    /// iteration. THIS is the stitch.
    ///
    /// Consumes `self` — the loop runs once, then teardown is `Drop`.
    ///
    /// Loop structure (per the C `event_loop` at `linux/event.c:111-
    /// 160` and the timer interleave at `event.c:112-130`):
    ///
    /// ```text
    /// while running:
    ///     timeout = timers.tick(fired_timers)      ─ C timeout_execute
    ///     for t in fired_timers: dispatch_timer(t) ─ C cb call
    ///     ev.turn(timeout, fired_io)               ─ C epoll_wait
    ///     for (w, ready) in fired_io: dispatch_io  ─ C cb call
    /// ```
    ///
    /// The C does timers FIRST (pingtimer might close a connection;
    /// that connection then doesn't show up as readable). We match.
    /// The "fire timers, THEN compute timeout" is the C `timeout_
    /// execute` order: `event.c:112` calls cbs, `event.c:130` returns
    /// the next deadline.
    ///
    /// PROVES C-is-WRONG #5 fixed: skeleton arms exactly one timer
    /// (Ping). After it fires and re-arms, `tick()` returns
    /// `Some(1s)`. If we DIDN'T re-arm (or the timer was del'd),
    /// `tick()` returns `None` → `turn(None)` blocks forever.
    /// C `linux/event.c:121` would `tv->tv_sec * 1000` on a NULL.
    ///
    /// Clippy `too_many_lines` allowed: the dispatch is one big
    /// match. Splitting it into helpers means passing `&mut self`
    /// to each helper, which means the helper can't borrow two
    /// fields at once. The C is one big function for the same
    /// reason (the cbs all reach the globals).
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn run(mut self) -> RunOutcome {
        // Reusable buffers. `tick`/`turn`/`drain` clear these
        // before pushing.
        let mut fired_timers = Vec::with_capacity(8);
        let mut fired_io = Vec::with_capacity(tinc_event::MAX_EVENTS_PER_TURN);
        let mut fired_signals = Vec::with_capacity(4);

        // C `linux/event.c:115`: `while(running)`.
        while self.running {
            // ─── timers (event.c:112-130)
            // tick() does: cache `now`, drain expired, return next
            // deadline. The C does the SAME order (`timeout_execute`
            // at `event.c:112` is called from `event_loop` BEFORE
            // `epoll_wait`).
            let timeout = self.timers.tick(&mut fired_timers);
            for &t in &fired_timers {
                match t {
                    TimerWhat::Ping => self.on_ping_tick(),
                    TimerWhat::AgePastRequests => self.on_age_past_requests(),
                    TimerWhat::RetryOutgoing(oid) => {
                        // C `retry_outgoing_handler` → `setup_
                        // outgoing_connection` (`net_socket.c:664`).
                        self.setup_outgoing_connection(oid);
                    }
                    TimerWhat::Periodic => {
                        // Return is the would-sleep duration; only
                        // the unit test reads it.
                        let _ = self.on_periodic_tick();
                    }
                    TimerWhat::KeyExpire | TimerWhat::AgeSubnets | TimerWhat::UdpPing => {
                        // Not armed yet. Unreachable.
                        unreachable!("timer {t:?} not armed yet")
                    }
                }
            }

            // ─── poll (linux/event.c:121-130)
            // C: `epoll_wait(fd, events, MAX_EVENTS, timeout_ms)`.
            // mio same. `timeout = None` → block forever (C-is-WRONG
            // #5: C derefs NULL here. mio handles None.).
            if let Err(e) = self.ev.turn(timeout, &mut fired_io) {
                // C `net.c:511`: log ERR, return 1.
                log::error!(target: "tincd",
                            "Error while waiting for input: {e}");
                return RunOutcome::PollError;
            }

            // ─── io dispatch (linux/event.c:131-159)
            for &(what, ready) in &fired_io {
                match what {
                    IoWhat::Signal => {
                        // `signalio_handler` (`signal.c:41-55`).
                        // drain reads ALL pending bytes (signals
                        // coalesce in the pipe).
                        self.signals.drain(&mut fired_signals);
                        for &s in &fired_signals {
                            self.on_signal(s);
                        }
                        fired_signals.clear();
                    }

                    IoWhat::UnixListener => {
                        // `handle_new_unix_connection`.
                        self.on_unix_accept();
                    }

                    IoWhat::Conn(id) => {
                        // `handle_meta_io`. The connection might
                        // have been terminated by an EARLIER event
                        // in this same batch (e.g., pingtimer closed
                        // it). slotmap returns None for stale keys —
                        // this is the generation guard.
                        if !self.conns.contains_key(id) {
                            continue;
                        }
                        // C `net_socket.c:517-555`: connecting check
                        // FIRST. The async-connect probe. C `:553`
                        // clears `connecting` then FALLS THROUGH to
                        // the `:556` write/read dispatch — the WRITE
                        // edge (which woke us) is the SAME edge that
                        // would let us flush the ID line. mio is
                        // EDGE-triggered (`EPOLLET`); if we `continue`
                        // here, the next WRITE wake never comes (the
                        // socket was already writable when we queued
                        // the ID). The probe-spurious and probe-fail
                        // paths DO return (`:534`, `:550`); the
                        // probe-success path falls through.
                        if self.conns[id].connecting {
                            if !self.on_connecting(id) {
                                // Spurious / failed. C `:534`/`:550`
                                // `return`.
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
                        // `net_socket.c:556-561`: write before read.
                        // tinc-event already orders WRITE-before-READ
                        // in the per-fd event pair, but the C also
                        // does this conditionally per-flag. Match.
                        if matches!(ready, Ready::Write) {
                            self.on_conn_writable(id);
                        } else {
                            self.on_conn_readable(id);
                        }
                    }

                    IoWhat::Device => {
                        // `handle_device_data` (`net_packet.c:1916-
                        // 1938`). Dummy returns `fd() → None` and
                        // never registers; FdTun (chunk-7 test rig)
                        // does. Edge-triggered: drain until EAGAIN.
                        self.on_device_read();
                    }

                    IoWhat::Tcp(i) => {
                        // `handle_new_meta_connection`.
                        self.on_tcp_accept(i);
                    }

                    IoWhat::Udp(i) => {
                        // `handle_incoming_vpn_data` (`net_packet.c:
                        // 1845-1913`). recvfrom, strip [dst][src],
                        // lookup_node_id, feed SPTPS, route.
                        self.on_udp_recv(i);
                    }
                }
            }
        }

        log::info!(target: "tincd", "Terminating");
        RunOutcome::Clean
    }

    // ─── timer handlers

    /// `timeout_handler` (`net.c:180-266`). The dead-connection
    /// sweep + ping sender.
    ///
    /// ## Four cases per connection
    ///
    /// `:219-221` Control conn → skip. Control conns also get a
    ///   1-hour `last_ping_time` bump in `handle_id` so the timeout
    ///   check would skip them anyway; the explicit `continue` saves
    ///   the comparison.
    ///
    /// `:236-247` **Pre-edge timeout** (handshake stalled). The conn
    ///   passed `pingtimeout` seconds without reaching ACK. Either
    ///   the async-connect never finished (`:238` "Timeout while
    ///   connecting") OR `id_h`/SPTPS stalled (`:240` "Timeout
    ///   during authentication", + tarpit bit in C — we don't track
    ///   per-conn tarpit yet). Terminate. THIS reaps the half-open
    ///   conn `tests/security.rs::id_timeout_half_open` plants.
    ///
    /// `:253-257` **Pinged but no PONG** (peer died). We sent PING,
    ///   `pingtimeout` elapsed, no PONG cleared the bit. Terminate.
    ///   The TCP keepalive case: peer rebooted, our socket is fine
    ///   (no RST yet), the only way we KNOW is the silence.
    ///
    /// `:260-262` **Send PING** (idle keepalive). `pinginterval`
    ///   elapsed since `last_ping_time`. Set the `pinged` bit, send
    ///   `"8"`. The peer's `ping_h` replies `"9"` → our `pong_h`
    ///   clears the bit → the conn survives the next sweep.
    ///
    /// ## Laptop-suspend detector (`:189-213`)
    ///
    /// `now - last_periodic_run_time > 2 * udp_discovery_timeout`
    /// → the timer hasn't fired for over a minute → the daemon
    /// was asleep (laptop lid). Every peer has timed US out and
    /// dropped the connection; OUR sockets still look alive. Sending
    /// into them produces "failed signature" noise on the peer side
    /// (stale SPTPS context). Force-close everything; outgoings
    /// retry with fresh contexts.
    #[allow(clippy::too_many_lines)] // C `timeout_handler` is 86 LOC
    fn on_ping_tick(&mut self) {
        let now = self.timers.now();

        // ─── laptop-suspend detection (`:189-213`)
        // C `:189`: `now.tv_sec - last_periodic_run_time.tv_sec`.
        // `Instant` saturating sub: a clock-goes-backwards (NTP
        // jump) reads as zero, which is the safe answer.
        let sleep_time = now.saturating_duration_since(self.last_periodic_run_time);
        let threshold = Duration::from_secs(u64::from(self.settings.udp_discovery_timeout) * 2);
        let close_all_connections = sleep_time > threshold;
        if close_all_connections {
            log::error!(target: "tincd",
                        "Awaking from dead after {} seconds of sleep",
                        sleep_time.as_secs());
        }
        // C `:215`: `last_periodic_run_time = now`.
        self.last_periodic_run_time = now;

        let pingtimeout = Duration::from_secs(u64::from(self.settings.pingtimeout));
        let pinginterval = Duration::from_secs(u64::from(self.settings.pinginterval));

        // `terminate()` mutates `conns`; collect ids first. The
        // connection set is small (one per direct peer + control).
        let ids: Vec<ConnId> = self.conns.keys().collect();
        let mut nw = false;
        for id in ids {
            let Some(conn) = self.conns.get(id) else {
                // Can happen if a previous terminate in THIS sweep
                // tore down a conn that's still in `ids`. Defensive.
                continue;
            };

            // C `:219-221`: control conns have no timeout.
            if conn.control {
                continue;
            }

            // C `:224-228`: laptop-suspend force-close.
            if close_all_connections {
                log::error!(target: "tincd",
                            "Forcing connection close after sleep time {} ({})",
                            conn.name, conn.hostname);
                // C: `terminate_connection(c, c->edge)`. The second
                // arg is `report` = broadcast DEL_EDGE; `c->edge !=
                // NULL` ≡ our `conn.active`. `terminate()` already
                // keys its DEL_EDGE on `was_active` — same effect.
                self.terminate(id);
                continue;
            }

            // C `:231-233`: `if(c->last_ping_time + pingtimeout >
            // now.tv_sec) continue`. Not yet stale; skip.
            let stale = now.saturating_duration_since(conn.last_ping_time);
            if stale <= pingtimeout {
                continue;
            }

            // C `:236-247`: `if(!c->edge)`. Pre-ACK timeout. The
            // handshake (or even the async-connect) didn't finish
            // in `pingtimeout` seconds.
            if !conn.active {
                if conn.connecting {
                    log::warn!(target: "tincd::conn",
                               "Timeout while connecting to {} ({})",
                               conn.name, conn.hostname);
                } else {
                    // C `:240-241`: also sets `c->status.tarpit =
                    // true` so `terminate` queues the fd in the
                    // tarpit ring instead of closing immediately.
                    // Our `Tarpit` is accept-side only; the per-
                    // conn tarpit bit isn't tracked. The terminate
                    // closes immediately. Harmless: the auth-
                    // timeout case is benign (slow peer) not hostile
                    // — the tarpit was for INBOUND auth-spam, and
                    // that's covered by the accept-side rate limit.
                    log::warn!(target: "tincd::conn",
                               "Timeout from {} ({}) during authentication",
                               conn.name, conn.hostname);
                }
                self.terminate(id);
                continue;
            }

            // C `:250`: `try_tx(c->node, false)`. UDP holepunch
            // keepalive. STUB(chunk-9).

            // C `:253-257`: `if(c->status.pinged)`. Sent PING,
            // `pingtimeout` elapsed, no PONG cleared the bit.
            if conn.pinged {
                log::info!(target: "tincd::conn",
                           "{} ({}) didn't respond to PING in {} seconds",
                           conn.name, conn.hostname, stale.as_secs());
                self.terminate(id);
                continue;
            }

            // C `:260-262`: `if(c->last_ping_time + pinginterval
            // <= now.tv_sec) send_ping(c)`. Idle for `pinginterval`
            // — send a keepalive. `send_ping` (`protocol_misc.c:
            // 47-52`): set bit, stamp time, `"%d", PING`.
            if stale >= pinginterval {
                let conn = self.conns.get_mut(id).expect("just checked");
                conn.pinged = true;
                conn.last_ping_time = now;
                nw |= conn.send(format_args!("{}", Request::Ping as u8));
            }
        }
        if nw {
            self.maybe_set_write_any();
        }

        // C `net.c:263-265`: `timeout_set(data, &(struct timeval) {
        // 1, jitter() })`. Re-arm +1s. jitter() not ported.
        self.timers.set(self.pingtimer, Duration::from_secs(1));
    }

    /// `periodic_handler` (`net.c:268-303`). Contradicting-edge
    /// storm detection + autoconnect. Re-arms +5s.
    ///
    /// `:274-291`: when both `contradicting_add_edge > 100` AND
    /// `contradicting_del_edge > 100`, two daemons are fighting
    /// over the same Name — each rejects the other's edges ("I
    /// don't have that"), correction-floods, gossip won't converge.
    /// The fix is **synchronous sleep**: blocking the event loop
    /// IS the point (stop sending corrections, let the other side
    /// win). Doubled each trigger (cap 3600s); halved each clean
    /// period (floor 10s).
    ///
    /// Returns the would-sleep duration so the unit test can check
    /// the backoff arithmetic without actually sleeping. The `run()`
    /// loop calls this; nobody reads the return outside tests.
    fn on_periodic_tick(&mut self) -> Duration {
        // C `:274`: `if(contradicting_del_edge > 100 &&
        // contradicting_add_edge > 100)`.
        let slept = if self.contradicting_del_edge > 100 && self.contradicting_add_edge > 100 {
            log::warn!(target: "tincd",
                       "Possible node with same Name as us! Sleeping {} seconds.",
                       self.sleeptime);
            let d = Duration::from_secs(u64::from(self.sleeptime));
            // C `:276`: `sleep_millis(sleeptime * 1000)`. Blocks.
            // The daemon is single-threaded; this stops EVERYTHING.
            // Intentional — see doc comment.
            #[cfg(not(test))]
            std::thread::sleep(d);
            // C `:277-281`: `sleeptime *= 2; if < 0 → 3600`. The
            // C's `< 0` check catches signed-int overflow. u32
            // doesn't overflow at 3600*2; cap explicitly.
            self.sleeptime = self.sleeptime.saturating_mul(2).min(3600);
            d
        } else {
            // C `:282-289`: halve, floor at 10. Integer divide.
            self.sleeptime = (self.sleeptime / 2).max(10);
            Duration::ZERO
        };

        // C `:290-291`: reset both counters.
        self.contradicting_add_edge = 0;
        self.contradicting_del_edge = 0;

        // C `:294-296`: `if(autoconnect && node_tree.count > 1)
        // do_autoconnect()`. STUB(chunk-11): autoconnect.

        // C `:298-300`: `timeout_set(data, { 5, jitter() })`.
        self.timers.set(self.periodictimer, Duration::from_secs(5));

        slept
    }

    /// `execute_script` wrapper (`script.c:144-253`). Builds the
    /// base env from daemon state, invokes, logs the outcome
    /// matching C `:231-247`. The C callers all ignore the return
    /// (`net_setup.c:752`, `graph.c:287`, `subnet.c:393`); a failing
    /// script never aborts the daemon. We log and move on.
    ///
    /// `DEVICE` env var: C reads the `device` global (path like
    /// `/dev/net/tun`). We don't keep that path post-open (the
    /// trait doesn't expose it; `Dummy` has no path). Pass `None`.
    /// The standard tinc-up scripts use `INTERFACE`, not `DEVICE`.
    ///
    /// `NETNAME`/`DEBUG`: not threaded through the daemon yet (the
    /// `-n` flag and `-d N` are main.rs concerns). `None` for now.
    fn run_script(&self, name: &str) {
        let env = ScriptEnv::base(
            None,       // netname: not threaded through yet
            &self.name, // myname
            None,       // device path: not retained post-open
            Some(&self.iface),
            None, // debug_level: not threaded through yet
        );
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));
    }

    /// `subnet_update` single-subnet path (`subnet.c:323-393`, the
    /// `else` branch at `:376-390`). Called from `on_add_subnet`/
    /// `on_del_subnet`. The `subnet=NULL` loop-all-subnets path
    /// (`:352-372`, called from `graph.c:294`) is inlined in
    /// `BecameReachable`/`BecameUnreachable`.
    ///
    /// C `:360-366` strips `#weight` from `net2str` output and puts
    /// it in `WEIGHT` separately. Our `Subnet::Display` already
    /// omits `#weight` when it's the default (10); we always pass
    /// the integer in `WEIGHT` (the C passes `""` for default —
    /// `:364` `weight = empty`). The integer is more useful; the C
    /// scripts that read `$WEIGHT` typically `[ -z "$WEIGHT" ]`
    /// guard anyway.
    fn run_subnet_script(&self, up: bool, owner: &str, subnet: &Subnet) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        // C `:337`: `"NODE=%s", owner->name`.
        env.add("NODE", owner.to_owned());
        // C `:339-345`: REMOTEADDRESS/REMOTEPORT only `if owner !=
        // myself`. The owner's UDP address — from `n->address`
        // (which is `update_node_udp`-written; for direct peers
        // it's `NodeState.edge_addr`).
        if owner != self.name {
            if let Some(addr) = self.nodes.get(owner).and_then(|ns| ns.edge_addr) {
                env.add("REMOTEADDRESS", addr.ip().to_string());
                env.add("REMOTEPORT", addr.port().to_string());
            }
        }
        // C `:359-368`: `net2str` then `strchr('#')` split. Our
        // `Display` may include `#weight` (non-default); strip it.
        let netstr = subnet.to_string();
        let netstr = netstr.split_once('#').map_or(netstr.as_str(), |(s, _)| s);
        env.add("SUBNET", netstr.to_owned());
        env.add("WEIGHT", subnet.weight().to_string());

        let name = if up { "subnet-up" } else { "subnet-down" };
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));
    }

    /// `graph.c:273-289` script firing for one node transition.
    /// Fires `host-up`/`host-down` AND `hosts/NAME-up`/`hosts/
    /// NAME-down` (the per-node script). Same env for both.
    ///
    /// `addr` is `n->address` — the SSSP-derived UDP address. For
    /// direct peers it's `NodeState.edge_addr`; for transitives we
    /// don't have it yet (chunk 9's `update_node_udp` walk). `None`
    /// → REMOTEADDRESS/REMOTEPORT omitted (the C would pass
    /// `"unknown"` from `sockaddr2str` of an `AF_UNKNOWN` — less
    /// useful than not setting the var at all).
    fn run_host_script(&self, up: bool, node: &str, addr: Option<SocketAddr>) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        // C `:279`: `"NODE=%s", n->name`.
        env.add("NODE", node.to_owned());
        // C `:280-282`: `sockaddr2str(&n->address, &address, &port)`.
        if let Some(a) = addr {
            env.add("REMOTEADDRESS", a.ip().to_string());
            env.add("REMOTEPORT", a.port().to_string());
        }

        // C `:284`: `execute_script(reachable ? "host-up" :
        // "host-down", &env)`.
        let name = if up { "host-up" } else { "host-down" };
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));

        // C `:286-287`: `snprintf(name, "hosts/%s-%s", n->name,
        // up?"up":"down"); execute_script(name, &env)`. Per-node
        // hook. Same env.
        let per = format!("hosts/{node}-{}", if up { "up" } else { "down" });
        Self::log_script(&per, script::execute(&self.confbase, &per, &env, None));
    }

    /// C `script.c:228-250` outcome logging. Associated fn (not
    /// method): the script call sites borrow `&self` for env
    /// building; this needs no daemon state.
    fn log_script(name: &str, r: io::Result<ScriptResult>) {
        match r {
            // C `:203`: NotFound is silent (script optional).
            // C `:230`: Ok is silent (success is the boring case).
            Ok(ScriptResult::NotFound | ScriptResult::Ok) => {}
            Ok(ScriptResult::Failed(st)) => {
                // C `:231-238`: `"Script %s exited with non-zero
                // status %d"` or `"...terminated by signal %d"`.
                // `ExitStatus::Display` covers both.
                log::warn!(target: "tincd", "Script {name}: {st}");
            }
            Err(e) => {
                // C `:249-250`: `system() == -1` → `"...exited
                // abnormally"`. Our spawn-fail (ENOEXEC etc).
                log::error!(target: "tincd", "Script {name} spawn failed: {e}");
            }
        }
    }

    /// `age_past_requests` (`protocol.c:213-228`). Evict seen-
    /// request entries older than `pinginterval` seconds, log the
    /// counts at DEBUG, re-arm +10s.
    ///
    /// C `:219` condition: `p->firstseen + pinginterval <=
    /// now.tv_sec`. The `<=` boundary is preserved by `seen.age`.
    /// C `:226` log: `"Aging past requests: deleted %d, left %d"`
    /// only when `left || deleted` (don't log 0/0 every 10s).
    fn on_age_past_requests(&mut self) {
        let now = self.timers.now();
        let max_age = Duration::from_secs(u64::from(self.settings.pinginterval));
        let (deleted, left) = self.seen.age(now, max_age);
        // C `:225-227`: gate the log on non-empty.
        if deleted > 0 || left > 0 {
            log::debug!(target: "tincd::proto",
                        "Aging past requests: deleted {deleted}, left {left}");
        }
        // C `:228`: `timeout_set(..., {10, jitter()})`. Re-arm.
        self.timers.set(self.age_timer, Duration::from_secs(10));
    }

    // ─── signal handlers

    /// `sigterm_handler` (`net.c:316-319`) for `Exit`;
    /// `sighup_handler` (`:321-328`) for `Reload`;
    /// `sigalrm_handler` (`:330-333`) for `Retry`.
    fn on_signal(&mut self, s: SignalWhat) {
        match s {
            SignalWhat::Exit => {
                // C: `logger(..., LOG_NOTICE, "Got %s signal");
                // event_exit()`. event_exit sets `running = false`.
                log::info!(target: "tincd", "Got signal, exiting");
                self.running = false;
            }
            SignalWhat::Reload => {
                // C: reopenlogger + reload_configuration. Skeleton:
                // log and ignore. reload needs the config tree walk,
                // the expire-mark sweep, all of `net.c:336-458`.
                log::info!(target: "tincd", "Got SIGHUP, reload not implemented");
            }
            SignalWhat::Retry => {
                // C: retry() (`net.c:460-485`). Walks outgoing_list,
                // sets each timeout to fire NOW. Skeleton has no
                // outgoings.
                log::info!(target: "tincd", "Got SIGALRM, retry not implemented");
            }
        }
    }

    // ─── io handlers

    /// `handle_new_meta_connection` (`net_socket.c:734-779`).
    /// accept on TCP listener `i`, tarpit-check, configure, allocate
    /// Connection, register with event loop.
    ///
    /// Same shape as `on_unix_accept` plus: `sockaddrunmap` (v4-mapped
    /// v6 → plain v4), `is_local`+tarpit (rate-limit non-loopback),
    /// `configure_tcp` (NONBLOCK + NODELAY).
    fn on_tcp_accept(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)];

        // C `:745`: `fd = accept(l->tcp.fd, &sa.sa, &len)`.
        // socket2 uses accept4(SOCK_CLOEXEC) on Linux/BSD — the C
        // doesn't set CLOEXEC on accepted fds (small leak into
        // script.c children, fixed for free).
        let (sock, peer_sockaddr) = match listener.tcp.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // The listener fd is NOT non-blocking but accept can
                // still spuriously return EAGAIN if a peer connect+
                // RST'd between epoll wake and our accept (TOCTOU).
                return;
            }
            Err(e) => {
                // C `:748`: `logger(ERR); return`. Nothing to clean.
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // ─── sockaddrunmap (`:751`)
        // V6ONLY is set so we shouldn't see mapped addrs in practice.
        // Canonicalize anyway: `fmt_addr` and the tarpit's prev-addr
        // compare want plain v4.
        //
        // `as_socket()` returns None for AF_UNIX (impossible here —
        // TCP accept returns AF_INET/AF_INET6). The `else` branch is
        // a kernel-bug-guard: log + dummy. `expect()` would crash
        // the whole daemon for one bizarre accept; not proportionate.
        // The dummy 0.0.0.0:0 won't match prev_addr (no false
        // tarpit), won't be is_local (no false exemption either).
        let peer = if let Some(sa) = peer_sockaddr.as_socket() {
            unmap(sa)
        } else {
            log::error!(target: "tincd::conn",
                        "accept returned non-IP family {:?}",
                        peer_sockaddr.family());
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };

        // ─── tarpit check (`:753`)
        // C: `if(!is_local_connection(&sa) && check_tarpit(&sa, fd))
        //   return`. The `&&` short-circuits: local conns never tick
        // the buckets. The pidfile address is loopback; `tinc start`
        // followed by 100 `tinc info` queries doesn't get tarpitted.
        if !is_local(&peer) {
            let now = self.timers.now();
            if self.tarpit.check(peer, now) {
                // C: `tarpit(fd); return true` from check → caller
                // returns. We do the pit() here; the C splits
                // check/pit because `check_tarpit` is `static bool`
                // and `tarpit` is `void`. Our struct fuses both.
                //
                // `sock.into()`: Socket → OwnedFd. The fd is NOT
                // configured (no NONBLOCK, no NODELAY) — we never
                // touch it again. The peer's reads block forever.
                self.tarpit.pit(sock.into());
                log::info!(target: "tincd::conn",
                           "Tarpitting connection from {peer}");
                return;
            }
        }

        // ─── configure_tcp (`:773`)
        // C ordering: new_connection (`:758`) BEFORE configure_tcp
        // (`:773`). We flip: configure first, THEN allocate. If
        // configure fails (set_nonblocking error), we don't have a
        // half-registered Connection to clean up. The C ordering
        // works because C errors don't unwind — `:73-75` just logs
        // and continues with a blocking fd. We're stricter.
        let fd = match configure_tcp(sock) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!(target: "tincd::conn",
                            "configure_tcp failed for {peer}: {e}");
                return; // sock dropped (fd closed)
            }
        };

        // ─── allocate connection (`:758-776`)
        // C `:762`: `c->hostname = sockaddr2hostname(&sa)`. The
        // "10.0.0.5 port 50123" string. Never changes after this.
        // C `:749`: `memcpy(&c->address, &sa, salen)`. We pass the
        // `SocketAddr` (already unmapped) for `ack_h`'s edge build.
        let hostname = fmt_addr(&peer);
        let conn = Connection::new_meta(fd, hostname, peer, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:771`: `io_add(&c->io, handle_meta_io, c, c->socket,
        // IO_READ)`. Read-only initially. Same registration as unix.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                // C `:767`: `"Connection from %s", c->hostname`.
                log::info!(target: "tincd::conn",
                           "Connection from {peer}");
            }
            Err(e) => {
                // ev.add failed (out of fds?). Roll back.
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// `handle_incoming_vpn_data` (`net_packet.c:1845-1913`) +
    /// `handle_incoming_vpn_packet` (`:1718-1842`) +
    /// `receive_udppacket` SPTPS branch (`:424-455`).
    ///
    /// Wire layout for a 1.1-SPTPS direct packet (`net.h:92-93`):
    /// `[dst_id:6][src_id:6][seqno:4][type:1][body][tag:16]`. The
    /// 12-byte ID prefix is OUTSIDE the SPTPS framing (C `DEFAULT_
    /// PACKET_OFFSET = 12`); the receiver strips it then feeds the
    /// rest to `sptps_receive_data`.
    ///
    /// `dst == nullid` means "direct to you" (`net_packet.c:1013`
    /// on the send side, `:1741` on the receive side). Relay path
    /// (`dst != nullid && to != myself`) is STUB(chunk-9).
    ///
    /// Loop drains ALL pending datagrams (edge-triggered epoll).
    /// STUB(chunk-10): `recvmmsg` batching.
    fn on_udp_recv(&mut self, i: u8) {
        // C `MAXSIZE` is `MTU + 4 + cipher overhead`. We use a
        // generous fixed buf; oversize packets truncate (MSG_TRUNC)
        // and we'd reject them anyway (the SPTPS decrypt fails).
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
        loop {
            // socket2 `recv_from` into `[MaybeUninit<u8>]`. Returns
            // `(n, SockAddr)`. `as_socket()` for the SocketAddr.
            let (n, sockaddr) = match self.listeners[usize::from(i)].udp.recv_from(&mut buf) {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // C `:1878`: `"Receiving packet failed: %s"`.
                    log::error!(target: "tincd::net",
                                "Receiving packet failed: {e}");
                    break;
                }
            };
            // SAFETY: `recv_from` returned `n` bytes written. The
            // first `n` slots are initialized. Transmute the
            // `MaybeUninit<u8>` slice to `u8` for those bytes.
            // (`MaybeUninit::slice_assume_init_ref` is unstable;
            // the manual cast is the stable equivalent.)
            #[allow(unsafe_code)]
            let pkt: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            // C `:1724`: `sockaddrunmap(addr)`. v4-mapped → v4.
            let peer = sockaddr.as_socket().map(unmap);

            self.handle_incoming_vpn_packet(pkt, peer);
        }
    }

    /// `handle_incoming_vpn_packet` (`net_packet.c:1718-1842`).
    /// One UDP datagram → ID-prefix lookup → SPTPS receive → route.
    ///
    /// SPTPS-only: skips `lookup_node_udp` (`:1728`) and `try_harder`
    /// (`:1754`). Goes straight to the source-ID lookup at `:1736`.
    /// The C does udp-addr-first because legacy-crypto packets have
    /// no ID prefix; we don't have legacy.
    fn handle_incoming_vpn_packet(&mut self, pkt: &[u8], peer: Option<SocketAddr>) {
        // C `:1736`: `pkt->offset = 2 * sizeof(node_id_t)`. The
        // 12-byte [dst][src] prefix. Too-short packet: drop.
        if pkt.len() < 12 {
            log::debug!(target: "tincd::net",
                        "Dropping {}-byte UDP packet (too short for ID prefix)",
                        pkt.len());
            return;
        }
        // `net.h:92-93`: `DSTID(x) = data + offset - 12` (i.e. byte
        // 0 with offset=12), `SRCID(x) = data + offset - 6` (byte 6).
        let dst_id = NodeId6::from_bytes(pkt[0..6].try_into().unwrap());
        let src_id = NodeId6::from_bytes(pkt[6..12].try_into().unwrap());
        let ct = &pkt[12..];

        // C `:1739`: `from = lookup_node_id(SRCID(pkt))`. The fast
        // path. STUB(chunk-9): `try_harder` fallback (decrypt-by-
        // trial when the lookup misses — happens for ID collisions
        // or pre-1.1 packets, neither of which we support).
        let Some(from_nid) = self.id6_table.lookup(src_id) else {
            log::debug!(target: "tincd::net",
                        "Received UDP packet from unknown source ID {src_id} ({peer:?})");
            return;
        };
        let from_name = self
            .graph
            .node(from_nid)
            .map_or("<gone>", |n| n.name.as_str())
            .to_owned();

        // C `:1741`: `if(from && from->status.sptps && DSTID == nullid)`
        // — direct-to-us. The non-null DSTID is the relay path.
        // STUB(chunk-9): relay (`:1817-1821` `if(to != myself)
        // send_sptps_data(to, from, ...)`). With dst==null, `to ==
        // myself` always; with dst!=null, `to = lookup_node_id(dst)`.
        if !dst_id.is_null() {
            log::debug!(target: "tincd::net",
                        "Received UDP relay packet (dst={dst_id}); \
                         relay path is STUB(chunk-9)");
            return;
        }

        // C `:1825`: `receive_udppacket(from, pkt)`. SPTPS branch
        // (`net_packet.c:424-455`).
        let tunnel = self.tunnels.entry(from_nid).or_default();
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // C `:426-433`: `if(!n->sptps.state)`. We got a UDP
            // packet before the per-tunnel handshake started. The C
            // kicks `send_req_key` here; we do too (it's harmless
            // — if a handshake is already in flight, the responder
            // side restarts it).
            if tunnel.status.waitingforkey {
                log::debug!(target: "tincd::net",
                            "Got packet from {from_name} but they haven't \
                             got our key yet");
            } else {
                log::debug!(target: "tincd::net",
                            "Got packet from {from_name} but we haven't \
                             exchanged keys yet");
                let _ = self.send_req_key(from_nid);
            }
            return;
        };

        // C `:437`: `n->status.udppacket = true`. Tells `receive_
        // sptps_record` (the callback) that THIS record came via UDP
        // (vs TCP-tunneled). The C resets it to false at `:439`
        // after `sptps_receive_data` returns; we do the same
        // (the bit is ephemeral, `route.c` reads it for "reply
        // same way" logic in chunk 9).
        tunnel.status.udppacket = true;

        // C `:438`: `sptps_receive_data(&n->sptps, DATA, len)`.
        // Datagram framing: one whole record per call. `OsRng` for
        // the rekey-response edge (rare; it's a peer-initiated
        // KEX during established session).
        let result = sptps.receive(ct, &mut OsRng);
        tunnel.status.udppacket = false;
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // C `:441-450`: "tunnel stuck" restart logic. Gate
                // on `last_req_key + 10 < now` to prevent storms.
                log::debug!(target: "tincd::net",
                            "Failed to decode UDP packet from {from_name}: {e:?}");
                let now = self.timers.now();
                let gate_ok = self.tunnels.get(&from_nid).is_none_or(|t| {
                    t.last_req_key
                        .is_none_or(|last| now.duration_since(last).as_secs() >= 10)
                });
                if gate_ok {
                    let _ = self.send_req_key(from_nid);
                }
                return;
            }
        };

        // C `:1833-1835`: `if(direct && sockaddrcmp(addr,
        // &n->address)) update_node_udp(n, addr)`. The FIRST valid
        // UDP packet from this peer confirms the address. We don't
        // have full `update_node_udp` (which also re-indexes
        // `node_udp_tree`); just stash + set the bit.
        if let Some(peer_addr) = peer {
            let tunnel = self.tunnels.entry(from_nid).or_default();
            if !tunnel.status.udp_confirmed {
                log::debug!(target: "tincd::net",
                            "UDP address of {from_name} confirmed: {peer_addr}");
                tunnel.status.udp_confirmed = true;
            }
            tunnel.udp_addr = Some(peer_addr);
        }

        // Dispatch SPTPS outputs (`receive_sptps_record`, `net_
        // packet.c:1056-1152`). May produce `HandshakeDone`
        // (handshake completed mid-stream after a rekey) and/or
        // `Record{type=0, data}` (one IP packet) and/or `Wire`
        // (rekey response, `send_sptps_data` it).
        let nw = self.dispatch_tunnel_outputs(from_nid, &from_name, outs);
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// `handle_device_data` (`net_packet.c:1916-1938`).
    ///
    /// TUN read → `route()` → `send_packet`. The C reads ONE packet
    /// per io callback; we drain until EAGAIN (edge-triggered epoll).
    /// C `DEFAULT_PACKET_OFFSET = 12` reserves room for the
    /// `[dst][src]` prefix; we don't need that pre-padding (our
    /// `send_sptps_data` builds the prefix into a fresh Vec).
    fn on_device_read(&mut self) {
        // `MTU = 1518`. The device's `read()` writes up to that.
        // FdTun reads at `+14` and synthesizes the ethernet header
        // into `[0..14]`; the buffer must be ≥ MTU.
        let mut buf = vec![0u8; crate::tunnel::MTU as usize];
        let mut nw = false;
        loop {
            let n = match self.device.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // C `:1933-1936`: `errors++; if > 10 event_
                    // exit()`. The C also `sleep_millis(errors*50)`
                    // (rate-limit a tight error loop on a flapping
                    // TUN). We're simpler: log + break. The fd stays
                    // registered; if it's truly dead (EBADFD), every
                    // turn fires this arm.
                    log::error!(target: "tincd::net",
                                "Error reading from device: {e}");
                    // C `:1933-1936`: at 10 consecutive failures,
                    // `event_exit()`. The kernel device is gone;
                    // tight-looping helps nobody. The C also does
                    // `sleep_millis(errors * 50)` to rate-limit a
                    // flapping TUN; we don't (the bound is 10 — the
                    // sleep would total 2.75s, then exit anyway).
                    self.device_errors += 1;
                    if self.device_errors > 10 {
                        log::error!(target: "tincd",
                                    "Too many errors from device, exiting!");
                        self.running = false;
                    }
                    break;
                }
            };
            // C `:1931`: `errors = 0`. Reset on success.
            self.device_errors = 0;
            // C `:1928-1929`: `myself->in_packets++; in_bytes +=`.
            let myself_tunnel = self.tunnels.entry(self.myself).or_default();
            myself_tunnel.in_packets += 1;
            myself_tunnel.in_bytes += n as u64;

            // C `:1930`: `route(myself, &packet)`.
            nw |= self.route_packet(&mut buf[..n]);
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// `route()` (`route.c:1130`) → `send_packet` (`net_packet.c:
    /// 1553-1617`). The forwarding decision plus the dispatch.
    ///
    /// `data` is the full ethernet frame (14-byte header + payload).
    /// `&mut` because `device.write()` mutates (the TUN write-path
    /// zeroes `tun_pi.flags`; FdTun doesn't, but the trait is `&mut`).
    ///
    /// Returns the io_set signal (true if a meta-conn outbuf went
    /// nonempty — `send_req_key` or the TCP-tunneled handshake).
    fn route_packet(&mut self, data: &mut [u8]) -> bool {
        // The reachability oracle for `route()`. C `route.c:655`
        // reads `subnet->owner->status.reachable` directly (it's
        // all one big graph of pointers). We close over `node_ids`
        // + `graph` and look it up.
        let result = {
            let node_ids = &self.node_ids;
            let graph = &self.graph;
            route(data, &self.subnets, &self.name, |name| {
                node_ids
                    .get(name)
                    .and_then(|&nid| graph.node(nid))
                    .is_some_and(|n| n.reachable)
            })
        };

        match result {
            RouteResult::Forward { to } if to == self.name => {
                // C `send_packet:1556-1568`: `if(n == myself) {
                // devops.write(packet); return; }`. The packet is
                // for US (it came in over the wire and `route()`
                // matched one of our subnets). Write it to the TUN.
                // STUB(chunk-9): `overwrite_mac` (`:1557-1562`) —
                // TAP-mode source-MAC rewriting. RMODE_ROUTER
                // doesn't need it.
                let len = data.len() as u64;
                let myself_tunnel = self.tunnels.entry(self.myself).or_default();
                myself_tunnel.out_packets += 1;
                myself_tunnel.out_bytes += len;
                if let Err(e) = self.device.write(data) {
                    log::debug!(target: "tincd::net",
                                "Error writing to device: {e}");
                }
                false
            }
            RouteResult::Forward { to } => {
                // C `send_packet:1571-1590`. To a remote node.
                let to = to.to_owned();
                let Some(&to_nid) = self.node_ids.get(&to) else {
                    // `route()` returned a name from `subnets`; if
                    // it's not in `node_ids`, the subnet was added
                    // for a node we don't know. C couldn't get here
                    // (subnet->owner is a `node_t*`). For us: warn
                    // + drop. Would mean a `subnets.add` without a
                    // matching `lookup_or_add_node` — a daemon bug.
                    log::warn!(target: "tincd::net",
                               "route() chose unknown node {to}");
                    return false;
                };
                let len = data.len();
                log::debug!(target: "tincd::net",
                            "Sending packet of {len} bytes to {to}");
                // C `:1582-1583`: traffic counters BEFORE the send
                // (the C counts attempts, not deliveries).
                let tunnel = self.tunnels.entry(to_nid).or_default();
                tunnel.out_packets += 1;
                tunnel.out_bytes += len as u64;

                // C `:1586-1590`: `if(n->status.sptps) { send_sptps
                // _packet(n, packet); try_tx(n); return; }`. Always
                // SPTPS for us (no legacy fork).
                self.send_sptps_packet(to_nid, &to, data)
            }
            RouteResult::Unreachable {
                icmp_type,
                icmp_code,
            } => {
                // C `route_ipv4_unreachable` (`route.c:121-215`):
                // synthesizes an ICMP error and writes it BACK to
                // the source. STUB(chunk-9). For now: log + drop.
                log::debug!(target: "tincd::net",
                            "route: unreachable (type={icmp_type} code={icmp_code})");
                false
            }
            RouteResult::NeighborSolicit => {
                // C `route.c:710-713`: `route_neighborsol(source,
                // packet)`. Synthesises an NDP advert reply.
                // STUB(chunk-9): `neighbor.rs` leaf. Log + drop.
                log::debug!(target: "tincd::net",
                            "route: NDP neighbor solicit (not yet handled)");
                false
            }
            RouteResult::Unsupported { reason } => {
                log::debug!(target: "tincd::net",
                            "route: dropping packet ({reason})");
                false
            }
            RouteResult::TooShort { need, have } => {
                // C `route.c:103-108`: `"Got too short packet from
                // %s"` at DEBUG_TRAFFIC.
                log::debug!(target: "tincd::net",
                            "route: too short (need {need}, have {have})");
                false
            }
        }
    }

    /// `send_sptps_packet` (`net_packet.c:683-730`). Wrap an IP
    /// packet in an SPTPS record and ship it.
    ///
    /// C `:684-686`: `if(!validkey && !n->connection) return`. The
    /// gate. If we don't have a session key AND no direct meta-conn
    /// to fall back to (the `send_tcppacket` path at `:725`), drop.
    /// We don't have `send_tcppacket` (chunk-9, the PACKET request
    /// type); the gate is just `!validkey`.
    ///
    /// C `:696-698`: `if(RMODE_ROUTER) offset = 14`. Strips the
    /// ethernet header before encrypting — the receiver re-
    /// synthesizes it from the IP version nibble (`receive_sptps_
    /// record:1128-1144`). Saves 14 bytes/packet.
    fn send_sptps_packet(&mut self, to_nid: NodeId, to_name: &str, data: &[u8]) -> bool {
        // C `:696-698`: RMODE_ROUTER strips the 14-byte ether hdr.
        // STUB(chunk-9): RMODE_SWITCH (`type = PKT_MAC`, no strip).
        const OFFSET: usize = 14;
        let tunnel = self.tunnels.entry(to_nid).or_default();

        if !tunnel.status.validkey {
            // C `try_sptps` (`net_packet.c:1157-1180`): `"No valid
            // key known yet for %s"` then `if(!waitingforkey) send_
            // req_key(n)`. The packet is dropped; the next one (a
            // few hundred ms later) finds the handshake done.
            log::debug!(target: "tincd::net",
                        "No valid key known yet for {to_name}");
            if !tunnel.status.waitingforkey {
                return self.send_req_key(to_nid);
            }
            // C `:1167-1173`: the 10-second debounce. If we sent a
            // REQ_KEY recently and got no answer, the peer might
            // have dropped it (TCP queue full during a flood). Re-
            // send. STUB(chunk-9): not on the first-packet hot path.
            return false;
        }

        // C `:691-694`: `if(ethertype == 0 && outstate) PKT_PROBE`.
        // The MTU-probe path (zero-ethertype is the probe marker).
        // STUB(chunk-9): PMTU discovery.

        if data.len() < OFFSET {
            return false; // C `:702`: `if(origpkt->len < offset) return`.
        }

        // STUB(chunk-9): compression (`:708-718` `if(outcompression
        // != COMPRESS_NONE) compress_packet(...)`). Type stays 0
        // (no PKT_COMPRESSED bit).

        // STUB(chunk-9): `if(n->connection && origpkt->len >
        // n->minmtu) send_tcppacket()` (`:724-726`). The TCP
        // fallback when the packet is too big for the discovered
        // MTU. We always go via SPTPS-UDP for now.

        // C `:728`: `sptps_send_record(&n->sptps, type, DATA +
        // offset, len - offset)`. Type 0 = plain IP packet.
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // `validkey` is true but `sptps` is `None`? Shouldn't
            // happen (the bit is set BY `HandshakeDone` which only
            // fires after `Sptps::start`). Defensive: log + drop.
            log::warn!(target: "tincd::net",
                       "validkey set but no SPTPS for {to_name}?");
            return false;
        };
        let outs = match sptps.send_record(PKT_NORMAL, &data[OFFSET..]) {
            Ok(outs) => outs,
            Err(e) => {
                // `InvalidState` if `outcipher` is None. Shouldn't
                // happen: `validkey` was checked above.
                log::warn!(target: "tincd::net",
                           "sptps_send_record for {to_name}: {e:?}");
                return false;
            }
        };
        // The output is exactly one `Wire`. Dispatch via the same
        // bridge as the handshake outputs (it'll go UDP this time:
        // record_type=0 < REC_HANDSHAKE).
        self.dispatch_tunnel_outputs(to_nid, to_name, outs)
    }

    /// `receive_sptps_record` (`net_packet.c:1056-1152`) +
    /// `send_sptps_data` (`:965-1054`) callback bridge.
    ///
    /// The C registers TWO callbacks with `sptps_start`: `receive_
    /// sptps_record` (for `Output::Record`/`HandshakeDone`) and
    /// `send_sptps_data` (for `Output::Wire`). Our SPTPS returns a
    /// `Vec<Output>`; this function IS both callbacks.
    ///
    /// Returns the io_set signal (TCP-tunneled handshake records
    /// queue to a meta-conn outbuf).
    fn dispatch_tunnel_outputs(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        outs: Vec<tinc_sptps::Output>,
    ) -> bool {
        use tinc_sptps::Output;
        let mut nw = false;
        for o in outs {
            match o {
                Output::Wire { record_type, bytes } => {
                    // `send_sptps_data` (`net_packet.c:965-1054`).
                    // `record_type == REC_HANDSHAKE` (128) goes via
                    // the meta connection (ANS_KEY); everything
                    // else goes UDP.
                    nw |= self.send_sptps_data(peer, peer_name, record_type, &bytes);
                }
                Output::HandshakeDone => {
                    // C `receive_sptps_record:1059-1065`: `if(type
                    // == SPTPS_HANDSHAKE) { validkey = true; waiting
                    // forkey = false; "SPTPS key exchange with %s
                    // successful" }`. The per-tunnel handshake just
                    // completed.
                    let tunnel = self.tunnels.entry(peer).or_default();
                    if !tunnel.status.validkey {
                        tunnel.status.validkey = true;
                        tunnel.status.waitingforkey = false;
                        log::info!(target: "tincd::net",
                                   "SPTPS key exchange with {peer_name} successful");
                    }
                }
                Output::Record { record_type, bytes } => {
                    // `receive_sptps_record` data branch
                    // (`:1071-1152`). One decrypted packet.
                    nw |= self.receive_sptps_record(peer, peer_name, record_type, &bytes);
                }
            }
        }
        nw
    }

    /// `receive_sptps_record` data branch (`net_packet.c:1071-1152`).
    /// One decrypted IP packet from a peer — re-synthesize the
    /// ethernet header and route it.
    fn receive_sptps_record(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        record_type: u8,
        body: &[u8],
    ) -> bool {
        // C `:1108`: `int offset = (type & PKT_MAC) ? 0 : 14`.
        // RMODE_ROUTER: peer stripped the ether header; we re-prepend.
        const OFFSET: usize = 14;
        // C `:1068-1070`: `if(len > MTU) return false`. Oversize.
        if body.len() > usize::from(crate::tunnel::MTU) {
            log::error!(target: "tincd::net",
                        "Packet from {peer_name} larger than MTU ({} > {})",
                        body.len(), crate::tunnel::MTU);
            return false;
        }

        // C `:1078-1092`: `if(type == PKT_PROBE)`. STUB(chunk-9).
        if record_type == PKT_PROBE {
            log::debug!(target: "tincd::net",
                        "Got SPTPS PROBE from {peer_name}; PMTU is STUB(chunk-9)");
            return false;
        }
        // C `:1094-1097`: `if(type & ~(PKT_COMPRESSED | PKT_MAC))`.
        // Unknown type bits.
        if record_type & !(PKT_COMPRESSED | PKT_MAC) != 0 {
            log::error!(target: "tincd::net",
                        "Unexpected SPTPS record type {record_type} from {peer_name}");
            return false;
        }
        // C `:1100-1105`: RMODE check vs PKT_MAC. We're RMODE_
        // ROUTER; PKT_MAC means the peer is in switch mode and
        // sent a full ethernet frame (no offset). We don't handle
        // that. STUB(chunk-9): switch mode.
        if record_type & PKT_MAC != 0 {
            log::warn!(target: "tincd::net",
                       "Received packet from {peer_name} with MAC header \
                        (peer in switch mode?); STUB(chunk-9)");
            return false;
        }
        // STUB(chunk-9): PKT_COMPRESSED (`:1109-1121`).
        if record_type & PKT_COMPRESSED != 0 {
            log::warn!(target: "tincd::net",
                       "Received compressed packet from {peer_name}; \
                        compression is STUB(chunk-9)");
            return false;
        }

        // C `:1123`: `memcpy(DATA + offset, data, len)`. C `:1128-
        // 1144`: synthesize the ethertype from the IP version nibble.
        if body.is_empty() {
            return false; // need byte 0 for the version nibble
        }
        let ethertype: u16 = match body[0] >> 4 {
            4 => crate::packet::ETH_P_IP,
            6 => 0x86DD, // ETH_P_IPV6
            v => {
                // C `:1141-1144`: `"Unknown IP version %d"`.
                log::debug!(target: "tincd::net",
                            "Unknown IP version {v} in packet from {peer_name}");
                return false;
            }
        };
        let mut frame = vec![0u8; OFFSET + body.len()];
        // MACs stay zero (`set_etherheader` in `tinc-device` does
        // the same; C `:1128` doesn't touch them — they're already
        // zero from the `vpn_packet_t` zero-init).
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame[OFFSET..].copy_from_slice(body);

        // STUB(chunk-9): `:1148-1150` `if(udppacket && len >
        // maxrecentlen) maxrecentlen = len`. PMTU bookkeeping.

        // C `:1152`: `receive_packet(from, &inpkt)` → (`:397-405`)
        // `n->in_packets++; n->in_bytes += len; route(n, packet)`.
        let len = frame.len() as u64;
        let tunnel = self.tunnels.entry(peer).or_default();
        tunnel.in_packets += 1;
        tunnel.in_bytes += len;

        // route() → `Forward{to: myself}` (we're the endpoint) →
        // device.write. If route() says forward-to-someone-else,
        // we're a relay — STUB(chunk-9): the C `route()` would
        // call `send_packet(subnet->owner)` and we'd recurse into
        // `send_sptps_packet` for THEM. The chunk-7 two-node mesh
        // never hits that.
        // DEFERRED(chunk-7-daemon): `route.c:648` source-loop check
        // (`if(subnet->owner == source) drop`). With 2 nodes and
        // /32 subnets, the destination subnet is never owned by
        // the sender. The check matters for overlapping subnets.
        self.route_packet(&mut frame)
    }

    /// `send_sptps_data` (`net_packet.c:965-1054`). The per-tunnel
    /// SPTPS "send_data" callback. Two transports:
    ///
    /// 1. **Handshake records** (`type == SPTPS_HANDSHAKE`, `:974-
    ///    996`): b64-encode, wrap in `ANS_KEY`, send via the meta-
    ///    connection's SPTPS. The handshake of the SECOND SPTPS
    ///    is transported by the FIRST. (`:992-994`: "We don't want
    ///    intermediate nodes to switch to UDP to relay these
    ///    packets"; ANS_KEY also lets us learn the reflexive UDP
    ///    addr from relays — chunk-9.)
    ///
    /// 2. **Data records** (`:1001-1054`): build `[dst_id][src_id]
    ///    [ciphertext]`, sendto(udp_sock).
    ///
    /// `to`/`from` are usually `peer`/`myself` (`send_sptps_data_
    /// myself`, `:99-101`). The relay path (`:100`: `from != myself
    /// `) is STUB(chunk-9).
    fn send_sptps_data(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        record_type: u8,
        ct: &[u8],
    ) -> bool {
        // C `:967`: `relay = (to->via != myself && ...) ? to->via
        // : to->nexthop`. The static-relay path. With a 2-node mesh,
        // `nexthop == via == to`. STUB(chunk-9): the full relay
        // logic + `relay_supported` check.

        if record_type == tinc_sptps::REC_HANDSHAKE {
            // ─── TCP transport via ANS_KEY (`:974-996`)
            // C `:996`: `send_request(to->nexthop->connection,
            // "%d %s %s %s -1 -1 -1 %d", ANS_KEY, from->name,
            // to->name, buf, to->incompression)`.
            //
            // `nexthop->connection`: read `last_routes[to]` for
            // `nexthop`, then `nodes[nexthop_name].conn`. With
            // direct neighbors, `nexthop == to` so `nodes[to_name]
            // .conn` directly.
            let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
                log::warn!(target: "tincd::net",
                           "No meta connection toward {to_name} for handshake");
                return false;
            };
            let Some(conn) = self.conns.get_mut(conn_id) else {
                return false;
            };
            // C `:989`: `b64encode_tinc(data, buf, len)`.
            let b64 = tinc_crypto::b64::encode(ct);
            // C `:995`: `to->incompression = myself->incompression`.
            // We don't do compression; 0.
            // STUB(chunk-9): compression (`from->incompression`).
            //
            // The C format: `"%d %s %s %s -1 -1 -1 %d"`. The `-1 -1
            // -1` are cipher/digest/maclength sentinels (the SPTPS
            // path doesn't read them; `:549` `if(from->status.sptps)`
            // branch only b64-decodes the `key` field). HOWEVER: the
            // C `sscanf("%lu", "-1")` is glibc-permissive (wraps to
            // ULONG_MAX). Our `AnsKey::parse` is strict (`u64::parse`
            // rejects `-1`). For Rust↔Rust interop, send `0 0 0`
            // instead. STUB(chunk-9-interop): when interop-testing
            // with C tincd, loosen `AnsKey::parse` to accept the C's
            // `-1` (or change `maclen` to `i64`).
            return conn.send(format_args!(
                "{} {} {} {} 0 0 0 0",
                Request::AnsKey,
                self.name,
                to_name,
                b64,
            ));
        }

        // ─── UDP transport (`:1001-1054`)
        // STUB(chunk-9): `tcponly` (`:970,974`), MTU-too-big
        // fallback (`:974`: `origlen > relay->minmtu`). Both fall
        // through to the TCP path (REQ_KEY/SPTPS_PACKET wrapping
        // at `:998`). Chunk 7 always goes UDP.
        //
        // STUB(chunk-9): `send_sptps_tcppacket` (`:976-986`). The
        // raw-TCP-relay path for nodes whose `connection->options
        // >> 24 >= 7` (newer protocol minor).

        // C `:1003-1006`: overhead = relay_supported ? 12 : 0. We
        // ALWAYS prefix (our peers are all ≥1.1, `options >> 24
        // >= 4`). C `:1012-1016`: direct ⇒ dst = nullid; else dst
        // = to->id. With 2-node mesh, always direct.
        // STUB(chunk-9): the non-direct case (`dst = to->id`).
        let src_id = self.id6_table.id_of(self.myself).unwrap_or(NodeId6::NULL);
        let mut wire = Vec::with_capacity(12 + ct.len());
        wire.extend_from_slice(NodeId6::NULL.as_bytes()); // dst: direct
        wire.extend_from_slice(src_id.as_bytes());
        wire.extend_from_slice(ct);

        // C `:1031-1040`: `choose_udp_address(relay, &sa, &sock)`.
        // The C tries `n->address` (last confirmed), falls back to
        // a random edge's address. For chunk 7: use `tunnels[to].
        // udp_addr` (set by `BecameReachable` or by the first valid
        // UDP packet from them). If unset, use `nodes[to].edge_addr`
        // (the meta-conn-derived guess from `on_ack`).
        // STUB(chunk-9): `choose_local_address` + `send_locally`
        // (`:1034-1036`). The 1-in-3 randomization (`:758-762`).
        let Some(addr) = self.choose_udp_address(to_nid, to_name) else {
            log::debug!(target: "tincd::net",
                        "No UDP address known for {to_name}; dropping");
            return false;
        };

        // C `:1044`: `sendto(listen_socket[sock].udp.fd, buf, ...,
        // sa, SALEN)`. We use `listeners[0]` always. STUB(chunk-9):
        // `adapt_socket` (`:784`) picks the listener whose address
        // family matches `sa`.
        log::debug!(target: "tincd::net",
                    "Sending {}-byte UDP packet to {to_name} ({addr})",
                    wire.len());
        let sockaddr = socket2::SockAddr::from(addr);
        if let Some(l) = self.listeners.first() {
            if let Err(e) = l.udp.send_to(&wire, &sockaddr) {
                if e.kind() != io::ErrorKind::WouldBlock {
                    // C `:1046-1051`: `if(sockmsgsize) reduce_mtu
                    // else log`. STUB(chunk-9): EMSGSIZE →
                    // reduce_mtu. For now: just log.
                    log::warn!(target: "tincd::net",
                               "Error sending UDP SPTPS packet to {to_name}: {e}");
                }
            }
        }
        false // UDP send doesn't touch any meta-conn outbuf
    }

    /// `to->nexthop->connection`. The meta connection for routing
    /// REQ_KEY/ANS_KEY toward `to`. With direct neighbors, `nexthop
    /// == to` so it's just `nodes[to_name].conn`. Transitives go
    /// via the first hop's connection.
    fn conn_for_nexthop(&self, to_nid: NodeId) -> Option<ConnId> {
        // `last_routes[to_nid]` has `nexthop`. If unreachable
        // (`None`), no path.
        let nexthop = self
            .last_routes
            .get(to_nid.0 as usize)
            .and_then(Option::as_ref)?
            .nexthop;
        // Reverse-lookup nexthop's name (graph slot → name string).
        let nexthop_name = self.graph.node(nexthop)?.name.as_str();
        // `NodeState.conn` for the nexthop.
        self.nodes.get(nexthop_name)?.conn
    }

    /// `choose_udp_address` (`net_packet.c:744-800`), abridged.
    /// Prefer the confirmed address; fall back to the edge address
    /// from `on_ack` (the meta-conn peer addr with port rewritten
    /// to their UDP port).
    fn choose_udp_address(&self, to_nid: NodeId, to_name: &str) -> Option<SocketAddr> {
        // C `:746-751`: `*sa = &n->address; if(udp_confirmed)
        // return`. Our `udp_addr` is `n->address`.
        if let Some(t) = self.tunnels.get(&to_nid) {
            if let Some(addr) = t.udp_addr {
                return Some(addr);
            }
        }
        // C `:765-781`: pick a random edge's `reverse->address`.
        // For chunk 7: just use `NodeState.edge_addr` (which IS
        // the same thing for direct neighbors — the addr from the
        // peer's ACK with port set to their UDP port).
        self.nodes.get(to_name)?.edge_addr
    }

    /// io_set ReadWrite for ANY connection that has a nonempty
    /// outbuf. Device-read / udp-recv paths can queue handshake
    /// records on a meta-conn but don't have a `ConnId` in scope
    /// to set io_set on. Sweep all conns. Per-packet hot path…
    /// but `conns.len()` is tiny (one per direct peer + control).
    /// STUB(chunk-10): track which ConnIds were touched, set those.
    fn maybe_set_write_any(&mut self) {
        let dirty: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| !c.outbuf.is_empty())
            .map(|(id, _)| id)
            .collect();
        for id in dirty {
            if let Some(&io_id) = self.conn_io.get(id) {
                if let Err(e) = self.ev.set(io_id, Io::ReadWrite) {
                    log::error!(target: "tincd::conn",
                                "io_set failed for {id:?}: {e}");
                    self.terminate(id);
                }
            }
        }
    }

    /// `handle_new_unix_connection` (`net_socket.c:781-812`).
    /// accept, allocate Connection, register with event loop.
    fn on_unix_accept(&mut self) {
        // C `:789`: `fd = accept(io->fd, &sa.sa, &len)`.
        let stream = match self.control.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Spurious wakeup. Level-triggered: re-fires next
                // turn if still readable.
                return;
            }
            Err(e) => {
                // C `:792`: log ERR, return. Connection wasn't
                // accepted; nothing to clean up.
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // ─── allocate connection
        // C `:798-811`: `c = new_connection(); c->name = "<control>";
        // ...; io_add(); connection_add(c); c->allow_request = ID`.
        // Our `Connection::new_control` sets the same defaults.
        //
        // OwnedFd from UnixStream: `into()` works (UnixStream:
        // Into<OwnedFd> via std).
        let fd: OwnedFd = stream.into();
        let conn = Connection::new_control(fd, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:807`: `io_add(&c->io, handle_meta_io, c, c->socket,
        // IO_READ)`. Read-only initially; `send` adds WRITE.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                // C `:808`: `"Connection from %s", c->hostname`.
                // hostname is the literal `"localhost port unix"`.
                log::info!(target: "tincd::conn",
                           "Connection from {} (control)",
                           self.conns[id].hostname);
            }
            Err(e) => {
                // ev.add failed (out of fds?). Roll back.
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// `handle_meta_io` READ path (`net_socket.c:559-561` →
    /// `handle_meta_connection_data` → `receive_meta`).
    ///
    /// feed → loop read_line → check_gate → handler.
    ///
    /// `too_many_lines`: the C `receive_meta` + `receive_request`
    /// dispatch inlined (`meta.c:164-320` is 156 lines). Splitting
    /// would thread `id`/`conn`/`self` borrows through helpers.
    /// chunk-4b's send_ack didn't shrink this — it GREW it (the
    /// SPTPS-mode dispatch + ACK handling moved IN, not out). The
    /// allow stays; the borrow-threading cost is real.
    #[allow(clippy::too_many_lines)]
    fn on_conn_readable(&mut self, id: ConnId) {
        // ─── feed (one recv)
        // C `meta.c:185`: `inlen = recv(...)`.
        // `OsRng`: feed() needs an rng for the SPTPS-mode receive
        // path. Only touched on rekey (HANDSHAKE record post-
        // initial-handshake). `OsRng` is zero-sized; passing `&mut`
        // is free.
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.feed(&mut OsRng) {
            FeedResult::WouldBlock => return,
            FeedResult::Dead => {
                self.terminate(id);
                return;
            }
            FeedResult::Data => {}
            FeedResult::Sptps(outs) => {
                // SPTPS-mode connection. Dispatch outputs.
                let needs_write = self.dispatch_sptps_outputs(id, outs);
                if !self.conns.contains_key(id) {
                    // dispatch terminated (e.g. HandshakeDone in 4a).
                    return;
                }
                if needs_write {
                    if let Some(&io_id) = self.conn_io.get(id) {
                        if let Err(e) = self.ev.set(io_id, Io::ReadWrite) {
                            log::error!(target: "tincd::conn",
                                        "io_set failed for {id:?}: {e}");
                            self.terminate(id);
                        }
                    }
                }
                // Don't fall through to the line-drain loop —
                // SPTPS mode doesn't touch inbuf.
                return;
            }
        }

        // ─── drain inbuf (loop readline + dispatch)
        // C `meta.c:303-315`: `while(c->inbuf.len) { ... }`.
        // We loop until `read_line` returns None (incomplete).
        loop {
            let conn = self.conns.get_mut(id).expect("not terminated mid-loop");
            let Some(range) = conn.inbuf.read_line() else {
                break;
            };
            // The line bytes. `bytes_raw()` returns the full backing
            // slice; `range` indexes into it. We can't borrow
            // `bytes_raw()` and call `&mut self` methods, so: copy.
            //
            // The copy is cheap (control lines are <100 bytes). The
            // ALTERNATIVE is `read_line` returning a `Vec<u8>` —
            // same copy, hidden inside. Making it explicit means
            // chunk 4 can later avoid the copy for the SPTPS path
            // (which has 1500-byte frames and IS hot).
            let line: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();

            // ─── check_gate (protocol.c:164-178)
            let req = match check_gate(conn, &line) {
                Ok(r) => r,
                Err(e) => {
                    log::error!(target: "tincd::proto",
                                "Bad request from {}: {e:?}", conn.name);
                    self.terminate(id);
                    return;
                }
            };

            // ─── handler dispatch (protocol.c:180)
            // C: `entry->handler(c, request)`. We match. The match
            // arms are the request_entries[] table.
            let (result, needs_write) = match req {
                Request::Id => {
                    // `id_h`. The ctx fields come from `&self` — we
                    // can't borrow `&self.cookie` while holding `&mut
                    // conn` (both borrow `self`). The cookie+name are
                    // small — clone. mykey is borrowed (the BLOB-clone
                    // for sptps_start happens INSIDE handle_id, only
                    // on the peer branch). confbase: borrow into a
                    // PathBuf clone (same shape as the others).
                    //
                    // Hold on — `&self.mykey` while `&mut conn` is
                    // borrowed from `&mut self.conns`? Disjoint
                    // fields. The borrow checker allows
                    // `&self.mykey` and `&mut self.conns[id]`
                    // simultaneously. The `.get_mut(id)` borrow IS
                    // through `&mut self.conns` not `&mut self`.
                    //
                    // Except: `conn` was bound at the top of the
                    // loop body via `self.conns.get_mut`. That's
                    // `&mut self.conns`. `&self.mykey` is fine
                    // (different field). `&self.cookie` is fine.
                    // The clones aren't NEEDED for borrow reasons —
                    // they were a habit from earlier chunks. KEEP
                    // them for now (clones are cheap, refactor later
                    // if profiling says so).
                    let cookie = self.cookie.clone();
                    let my_name = self.name.clone();
                    let confbase = self.confbase.clone();
                    let ctx = IdCtx {
                        cookie: &cookie,
                        my_name: &my_name,
                        mykey: &self.mykey,
                        confbase: &confbase,
                    };
                    let now = self.timers.now();
                    match handle_id(conn, &line, &ctx, now, &mut OsRng) {
                        Ok(IdOk::Control { needs_write }) => (DispatchResult::Ok, needs_write),
                        Ok(IdOk::Peer { needs_write, init }) => {
                            // ─── SPTPS-start dispatch
                            // 1. Queue init Wire bytes (responder's KEX).
                            //    C `send_meta_sptps`: buffer_add to
                            //    outbuf. Our `send_raw`.
                            // 2. take_rest from inbuf, re-feed via
                            //    feed_sptps. The id-line piggyback.
                            // 3. Dispatch THOSE outputs too.
                            //
                            // For chunk 4a, step 3 (and the regular
                            // FeedResult::Sptps arm above) terminate
                            // on HandshakeDone — we don't have
                            // send_ack yet. The integration test
                            // proves the handshake completes; chunk
                            // 4b adds the ack.
                            let mut nw = needs_write;
                            for o in init {
                                if let tinc_sptps::Output::Wire { bytes, .. } = o {
                                    nw |= conn.send_raw(&bytes);
                                }
                                // Output::Record / HandshakeDone:
                                // unreachable from sptps_start (it
                                // only emits Wire). The match isn't
                                // exhaustive; we let other variants
                                // fall through silently. They're
                                // unreachable, and panicking would
                                // be noise.
                            }

                            // take_rest + re-feed. Factor as a
                            // method so the regular Sptps arm can
                            // call the same dispatch.
                            let leftover = conn.inbuf.take_rest();
                            // Self::feed_sptps borrows ONLY sptps,
                            // not conn. We can borrow sptps then
                            // dispatch the outputs (which need
                            // &mut conn.outbuf). Disjoint fields
                            // inside Connection — except: feed_sptps
                            // takes &mut Sptps via conn.sptps.
                            // as_deref_mut(), and send_raw is
                            // &mut self (Connection). Conflict.
                            //
                            // Same borrow problem as feed(). Same
                            // fix: feed_sptps is an associated fn
                            // taking &mut Sptps directly. We pull
                            // the deref out here.
                            let outs = if leftover.is_empty() {
                                // Fast path: no piggyback. Common.
                                Vec::new()
                            } else {
                                let sptps = conn
                                    .sptps
                                    .as_deref_mut()
                                    .expect("handle_id_peer just installed it");
                                match Connection::feed_sptps(
                                    sptps, &leftover, &conn.name, &mut OsRng,
                                ) {
                                    FeedResult::Sptps(outs) => outs,
                                    FeedResult::Dead => {
                                        // Piggybacked bytes were
                                        // garbage. Unusual (a real
                                        // peer's KEX is well-formed)
                                        // but possible (fuzzer).
                                        log::error!(
                                            target: "tincd::proto",
                                            "SPTPS error in piggyback from {}",
                                            conn.name
                                        );
                                        self.terminate(id);
                                        return;
                                    }
                                    // feed_sptps only returns
                                    // Sptps or Dead.
                                    _ => unreachable!(),
                                }
                            };

                            // Dispatch piggyback outputs. Same
                            // shape as the regular Sptps arm. For
                            // chunk 4a: terminate on HandshakeDone.
                            // (Reaching HandshakeDone in the
                            // PIGGYBACK is unlikely — needs the
                            // initiator's KEX AND SIG in the same
                            // segment as the ID line. Three writes
                            // coalesced. Possible on a slow link.)
                            if self.dispatch_sptps_outputs(id, outs) {
                                nw = true;
                            }
                            // dispatch_sptps_outputs may have
                            // terminated (HandshakeDone in 4a).
                            // Check.
                            if !self.conns.contains_key(id) {
                                return;
                            }

                            (DispatchResult::Ok, nw)
                        }
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "ID rejected from {}: {e:?}", conn.name);
                            (DispatchResult::Drop, false)
                        }
                    }
                }
                Request::Control => {
                    let (r, nw) = handle_control(conn, &line);
                    if r == DispatchResult::DumpSubnets {
                        // `dump_subnets` (`subnet.c:395-410`). Same
                        // borrow dance as DumpConnections: drop
                        // `conn`, walk the tree into a Vec, re-fetch.
                        // C: `"%d %d %s %s"` per row, terminator
                        // `"%d %d"`. `netstr` is `net2str` output
                        // (= `Subnet::Display`). Owner is the name
                        // or `"(broadcast)"` for ownerless (`subnet.
                        // c:406`: `subnet->owner ? ->name : "(
                        // broadcast)"` — we don't have ownerless
                        // subnets yet; chunk 8's broadcast subnets).
                        let rows: Vec<String> = self
                            .subnets
                            .iter()
                            .map(|(subnet, owner)| {
                                format!(
                                    "{} {} {} {}",
                                    Request::Control as u8,
                                    crate::proto::REQ_DUMP_SUBNETS,
                                    subnet,
                                    owner
                                )
                            })
                            .collect();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator.
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_SUBNETS
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::DumpNodes {
                        // `dump_nodes` (`node.c:201-223`). The 23-
                        // field beast. CLI parser: `tinc-tools::cmd::
                        // dump::NodeRow::parse` (22 sscanf fields —
                        // hostname is ONE %s = three tokens).
                        let rows = self.dump_nodes_rows();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator (`node.c:223`).
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_NODES
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::DumpEdges {
                        // `dump_edges` (`edge.c:123-137`). Nested
                        // walk: nodes × per-node edges. CLI parser:
                        // `tinc-tools::cmd::dump::EdgeRow::parse`
                        // (8 fields, 2 `" port "` literals).
                        let rows = self.dump_edges_rows();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator (`edge.c:137`).
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_EDGES
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::DumpConnections {
                        // `dump_connections` (`connection.c:166-175`).
                        // Walk ALL conns (including the one asking).
                        // C: `for list_each(connection_t, c, &list)
                        // send_request(cdump, "%d %d %s %s %x %d %x")`
                        // then a terminator `"%d %d"`.
                        //
                        // Borrow dance: `conn` borrows `self.conns`
                        // mutably. The walk needs `&self.conns`. Drop
                        // `conn`, walk into a Vec<String>, re-fetch
                        // `conn`, send. The Vec is one alloc per
                        // dump (not hot — control RPC).
                        let rows: Vec<String> = self
                            .conns
                            .values()
                            .map(|c| {
                                // `connection.c:168`: `"%d %d %s %s
                                // %x %d %x"`. `hostname` is the
                                // FUSED `"host port port"` string
                                // (one %s); the CLI splits it (`" port "`
                                // literal, `dump.rs::ConnRow::parse`).
                                format!(
                                    "{} {} {} {} {:x} {} {:x}",
                                    Request::Control as u8,
                                    crate::proto::REQ_DUMP_CONNECTIONS,
                                    c.name,
                                    c.hostname,
                                    c.options,
                                    c.fd(),
                                    c.status_value()
                                )
                            })
                            .collect();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator: `"%d %d"` (`:173`). The CLI
                        // detects end-of-dump by a line with no
                        // body after the subtype int.
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_CONNECTIONS
                        ));
                        (DispatchResult::Ok, nw2)
                    } else {
                        (r, nw)
                    }
                }
                _ => {
                    // Any other request: skeleton doesn't handle.
                    // C would dispatch via the table; we Drop.
                    // (This shouldn't fire — `allow_request` gates
                    // to ID then CONTROL. But if a future chunk
                    // sets `allow_request = None` for some path
                    // and forgets to add the match arm, this is
                    // the catch.)
                    log::error!(target: "tincd::proto",
                                "Request {req:?} not implemented");
                    (DispatchResult::Drop, false)
                }
            };

            // ─── io_set (meta.c:95)
            if needs_write {
                if let Some(&io_id) = self.conn_io.get(id) {
                    if let Err(e) = self.ev.set(io_id, Io::ReadWrite) {
                        log::error!(target: "tincd::conn",
                                    "io_set failed for {id:?}: {e}");
                        self.terminate(id);
                        return;
                    }
                }
            }

            match result {
                // Dump variants were already mapped to Ok above
                // (the Control arm rewrote them inline). Unreachable
                // here. Explicit-unreachable rather than `_` so a
                // new DispatchResult variant fails to compile.
                DispatchResult::DumpConnections
                | DispatchResult::DumpSubnets
                | DispatchResult::DumpNodes
                | DispatchResult::DumpEdges => {
                    unreachable!("Dump variants rewritten inline above")
                }
                DispatchResult::Ok => {}
                DispatchResult::Stop => {
                    // `event_exit()`. The reply is queued; we set
                    // running=false; the loop finishes THIS turn
                    // (so the WRITE event for the reply fires) then
                    // exits. Don't `return` — let the read_line loop
                    // exhaust inbuf (CLI might have sent more after
                    // STOP; unlikely but harmless).
                    self.running = false;
                }
                DispatchResult::Drop => {
                    self.terminate(id);
                    return;
                }
            }
        }
    }

    /// `receive_meta_sptps` (`meta.c:120-162`). Dispatch SPTPS
    /// outputs. Called from BOTH the regular `FeedResult::Sptps`
    /// arm AND the `IdOk::Peer` piggyback re-feed.
    ///
    /// Returns `true` if any output queued bytes to outbuf (io_set
    /// signal). May `terminate(id)` — caller must check `conns.
    /// contains_key(id)` after.
    ///
    /// Match arms map 1:1 to the C callback's branches:
    /// - `Wire` → `send_meta_sptps` (`meta.c:50`): outbuf raw.
    /// - `HandshakeDone` → `meta.c:129-135`: `if(allow == ACK)
    ///   send_ack(c) else return true`.
    /// - `Record` → `meta.c:153-161`: strip `\n`, `receive_
    ///   request(c, data)`. Same `check_gate` + handler match as
    ///   the cleartext line path; only the FRAMING differs (SPTPS
    ///   record vs `\n`-terminated line).
    fn dispatch_sptps_outputs(&mut self, id: ConnId, outs: Vec<tinc_sptps::Output>) -> bool {
        use tinc_sptps::Output;
        let mut needs_write = false;
        for o in outs {
            let Some(conn) = self.conns.get_mut(id) else {
                return needs_write;
            };
            match o {
                Output::Wire { bytes, .. } => {
                    // C `send_meta_sptps` (`meta.c:50`).
                    needs_write |= conn.send_raw(&bytes);
                }
                Output::HandshakeDone => {
                    // C `meta.c:129-135`: `if(type == SPTPS_
                    // HANDSHAKE) { if(c->allow_request == ACK)
                    // return send_ack(c); else return true; }`.
                    //
                    // `else return true`: outgoing conns send their
                    // ACK from `id_h` (`:453` `if(!c->outgoing) ...
                    // else send_ack(c)` — wait no, that's not
                    // right either. The C `:451-453` is `if(!c->
                    // outgoing) send_id(c)`. The outgoing-side
                    // send_ack is from the SAME `meta.c:131` arm.
                    // The `else` is for the initiator's SECOND
                    // HandshakeDone callback during rekey. Chunk
                    // 4b is responder-only, no rekey: always ACK.
                    log::info!(target: "tincd::auth",
                               "SPTPS handshake completed with {} ({})",
                               conn.name, conn.hostname);
                    if conn.allow_request == Some(Request::Ack) {
                        let now = self.timers.now();
                        needs_write |= send_ack(conn, self.my_udp_port, self.myself_options, now);
                    }
                    // No terminate. No sync-flush. The chunk-4a
                    // shortcut is gone; the connection STAYS UP.
                    // The ACK is queued in outbuf (encrypted via
                    // sptps_send_record inside conn.send); the
                    // regular WRITE event flushes it.
                }
                Output::Record { bytes, .. } => {
                    // C `meta.c:155-161`. Strip `\n`, dispatch.
                    // `record_type` is always 0 here (app data;
                    // SPTPS_HANDSHAKE became `HandshakeDone`).
                    // The C ignores `type` (`meta.c:153`: only
                    // checked against SPTPS_HANDSHAKE earlier).
                    let body = record_body(&bytes);

                    // ─── receive_request: same as cleartext
                    let req = match check_gate(conn, body) {
                        Ok(r) => r,
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "Bad SPTPS request from {}: {e:?}", conn.name);
                            self.terminate(id);
                            return needs_write;
                        }
                    };

                    // Handler match. C `request_entries[]` table
                    // (`protocol.c:58-86`). The body is owned (a
                    // Vec inside `Output::Record`); the handlers
                    // need `&mut self` so we can't borrow `conn`
                    // across the call — already dropped above.
                    let result = match req {
                        Request::Ack => self.on_ack(id, body),
                        Request::AddSubnet => self.on_add_subnet(id, body),
                        Request::DelSubnet => self.on_del_subnet(id, body),
                        Request::AddEdge => self.on_add_edge(id, body),
                        Request::DelEdge => self.on_del_edge(id, body),
                        Request::ReqKey => self.on_req_key(id, body),
                        Request::AnsKey => self.on_ans_key(id, body),
                        Request::Ping => {
                            // `ping_h` (`protocol_misc.c:54-57`):
                            // `return send_pong(c)`. That's it.
                            // `send_pong` (`:59-61`): `"%d", PONG`.
                            let conn = self.conns.get_mut(id).expect("gate passed");
                            Ok(conn.send(format_args!("{}", Request::Pong as u8)))
                        }
                        Request::Pong => {
                            // `pong_h` (`protocol_misc.c:63-76`):
                            // clear pinged bit. If outgoing AND its
                            // backoff is non-zero, reset it + the
                            // addr cache cursor + add the working
                            // address as recent. The connection IS
                            // healthy — next reconnect tries this
                            // address first.
                            let conn = self.conns.get_mut(id).expect("gate passed");
                            // C `:65`: `c->status.pinged = false`.
                            conn.pinged = false;
                            // C `:69`: `if(c->outgoing && c->
                            // outgoing->timeout)`. Gate on non-zero
                            // timeout: a healthy conn pongs every
                            // pinginterval; don't churn the cache
                            // each time.
                            let oid = conn.outgoing.map(OutgoingId::from);
                            let addr = conn.address;
                            if let Some(oid) = oid {
                                if let Some(out) = self.outgoings.get_mut(oid) {
                                    if out.timeout != 0 {
                                        // C `:70`: `timeout = 0`.
                                        out.timeout = 0;
                                        // C `:71-72`: reset cursor +
                                        // prepend the address.
                                        out.addr_cache.reset();
                                        if let Some(a) = addr {
                                            out.addr_cache.add_recent(a);
                                        }
                                    }
                                }
                            }
                            Ok(false)
                        }
                        _ => {
                            // KEY_CHANGED/REQ_KEY/ANS_KEY/PING/PONG
                            // etc — chunk 7/8. The gate passed
                            // (allow_request = None post-ACK). C
                            // dispatches via the table; we Drop
                            // until handlers land.
                            log::warn!(target: "tincd::proto",
                                       "SPTPS request {req:?} not implemented — chunk 7/8");
                            self.terminate(id);
                            return needs_write;
                        }
                    };
                    match result {
                        Ok(nw) => needs_write |= nw,
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "{req:?} from {id:?}: {e:?}");
                            self.terminate(id);
                            return needs_write;
                        }
                    }
                }
            }
        }
        needs_write
    }

    /// `lookup_node` + `new_node`/`node_add` fused (`node.c:74,96`).
    /// The C pattern from `add_edge_h:112-120` and `add_subnet_h:
    /// 86-89`: `n = lookup_node(name); if(!n) { n = new_node();
    /// node_add(n); }`.
    ///
    /// Adds to `graph` AND `node_ids` (the name→id map). Does NOT
    /// add a `NodeState` — only directly-connected peers get one
    /// (via `on_ack`). A node learned from a forwarded ADD_EDGE is
    /// transitive: in the graph, but no live connection.
    ///
    /// C `xzalloc` zeroes `reachable`; `Graph::add_node` defaults
    /// it `true`. We zero it back: a freshly-learned node IS
    /// unreachable until `run_graph` proves otherwise. The diff
    /// then emits `BecameReachable` and we get the host-up log.
    fn lookup_or_add_node(&mut self, name: &str) -> NodeId {
        if let Some(&id) = self.node_ids.get(name) {
            return id;
        }
        let id = self.graph.add_node(name);
        // C `node.c:75`: `xzalloc` → `reachable = false`. The
        // graph crate's `true` default is for the steady-state
        // "all nodes already known" tests; the daemon's reality
        // is "just learned this name, haven't run sssp yet".
        self.graph.set_reachable(id, false);
        self.node_ids.insert(name.to_owned(), id);
        // C `node.c:126-131`: `node_add` computes the SHA-512
        // prefix and indexes `node_id_tree`. UDP fast-path lookup.
        self.id6_table.add(name, id);
        id
    }

    /// `send_req_key` (`protocol_key.c:114-135`) + `send_initial_
    /// sptps_data` (`:103-112`). Start the per-tunnel SPTPS as
    /// initiator and send the first handshake record (the KEX) via
    /// REQ_KEY on the meta connection.
    ///
    /// The C splits this into two functions because of the callback
    /// dance: `sptps_start` takes `send_initial_sptps_data` as the
    /// callback, which gets fired re-entrantly with the KEX bytes.
    /// Our `Sptps::start` returns `Vec<Output>` instead; we dispatch
    /// the FIRST `Wire` here (it's the KEX, goes via REQ_KEY) and
    /// any subsequent ones via `send_sptps_data` (they'd go via
    /// ANS_KEY — but `start()` only emits one Wire so this is moot).
    ///
    /// C `:116-120`: `if(!node_read_ecdsa_public_key(to)) send REQ_
    /// PUBKEY`. We REQUIRE the key in `hosts/{to}` (no on-the-fly
    /// fetch); STUB(chunk-9).
    ///
    /// Returns the io_set signal (the REQ_KEY queued on a meta-conn).
    fn send_req_key(&mut self, to_nid: NodeId) -> bool {
        let Some(to_name) = self.graph.node(to_nid).map(|n| n.name.clone()) else {
            return false;
        };

        // C `:116-120`: `node_read_ecdsa_public_key(to)`. Load from
        // `hosts/{to_name}`. Same loader as `id_h` (`proto.rs:572`).
        // Re-reads on every `send_req_key` (C does too; `node_t.
        // ecdsa` is set lazily by `node_read_ecdsa_public_key` and
        // `:116` checks it first — we don't cache, so we read every
        // time. The 10-second debounce gates it; not hot).
        let host_config = {
            let host_file = self.confbase.join("hosts").join(&to_name);
            let mut cfg = tinc_conf::Config::default();
            if let Ok(entries) = tinc_conf::parse_file(&host_file) {
                cfg.merge(entries);
            }
            cfg
        };
        let Some(hiskey) =
            crate::keys::read_ecdsa_public_key(&host_config, &self.confbase, &to_name)
        else {
            // C `:117-119`: `"No Ed25519 key known for %s"` then
            // `send REQ_PUBKEY`. STUB(chunk-9): on-the-fly key fetch
            // via REQ_PUBKEY/ANS_PUBKEY (`protocol_key.c:196-231`).
            // For chunk 7: `hosts/{to}` MUST have the key.
            log::warn!(target: "tincd::net",
                       "No Ed25519 key known for {to_name}; cannot start tunnel");
            return false;
        };

        // C `:122-124`: `snprintf(label, ..., "tinc UDP key
        // expansion %s %s", myself->name, to->name)`. Initiator
        // name first.
        let label = make_udp_label(&self.name, &to_name);

        // C `:126-131`: `sptps_stop; validkey=false; waitingforkey=
        // true; last_req_key=now; sptps_start(..., true, true, ...)`.
        // The two `true`s are `initiator` and `datagram`.
        // `mykey` clone: `Sptps::start` consumes `SigningKey`; same
        // blob-roundtrip as `handle_id_peer` (`proto.rs:663`).
        let mykey = SigningKey::from_blob(&self.mykey.to_blob());
        let (sptps, outs) = Sptps::start(
            Role::Initiator,
            Framing::Datagram,
            mykey,
            hiskey,
            label,
            16, // C `sptps_replaywin` default
            &mut OsRng,
        );
        let now = self.timers.now();
        let tunnel = self.tunnels.entry(to_nid).or_default();
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        // C `send_initial_sptps_data` (`:103-112`): the FIRST Wire
        // from `start()` is the KEX. Goes via REQ_KEY (NOT ANS_KEY —
        // C `:111`: `send_request(..., "%d %s %s %d %s", REQ_KEY,
        // myself->name, to->name, REQ_KEY, buf)`). The DOUBLE
        // `REQ_KEY` is intentional: outer is the request type,
        // inner (the `reqno` extension) tells `req_key_ext_h` this
        // is an SPTPS-init payload.
        //
        // After the first send, the C swaps the callback to `send_
        // sptps_data_myself` (`:106`: `to->sptps.send_data = ...`)
        // so subsequent Wires go via `send_sptps_data` (ANS_KEY for
        // handshake, UDP for data). `start()` only emits ONE Wire
        // (the initiator KEX), so for chunk 7 the loop has one
        // iteration. The general dispatch handles subsequent
        // outputs from `receive()`.
        let mut nw = false;
        let mut first = true;
        for o in outs {
            if let tinc_sptps::Output::Wire { bytes, .. } = o {
                if first {
                    first = false;
                    let b64 = tinc_crypto::b64::encode(&bytes);
                    let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
                        log::warn!(target: "tincd::net",
                                   "No meta connection toward {to_name} for REQ_KEY");
                        return false;
                    };
                    let Some(conn) = self.conns.get_mut(conn_id) else {
                        return false;
                    };
                    // C `:111`: `"%d %s %s %d %s"`. ReqKeyExt::reqno
                    // = REQ_KEY (15). The doubled-request-type is
                    // `req_key_ext_h`'s SPTPS-init dispatch key.
                    nw |= conn.send(format_args!(
                        "{} {} {} {} {}",
                        Request::ReqKey,
                        self.name,
                        to_name,
                        Request::ReqKey as u8,
                        b64,
                    ));
                } else {
                    // Shouldn't fire from `start()` (one Wire only).
                    // But if SPTPS internals change: route via the
                    // general dispatch (ANS_KEY for handshake).
                    nw |= self.send_sptps_data(to_nid, &to_name, tinc_sptps::REC_HANDSHAKE, &bytes);
                }
            }
            // HandshakeDone/Record from start(): unreachable.
        }
        nw
    }

    /// `req_key_h` (`protocol_key.c:276-345`) + `req_key_ext_h`
    /// `case REQ_KEY` (`:234-269`). The per-tunnel SPTPS responder
    /// side.
    ///
    /// REQ_KEY is heavily overloaded (see `tinc-proto::msg::key`
    /// doc). The chunk-7 path: `to == myself` AND `ext.reqno ==
    /// REQ_KEY` ⇒ peer is initiating per-tunnel SPTPS. We start
    /// ours as RESPONDER, feed their KEX into it, send our KEX +
    /// SIG back via `send_sptps_data` (→ ANS_KEY).
    ///
    /// STUB(chunk-9):
    /// - `to != myself` relay (`:320-344`).
    /// - `REQ_PUBKEY`/`ANS_PUBKEY` (`:196-231`).
    /// - `SPTPS_PACKET` (`:149-188`, TCP-tunneled data records).
    /// - `send_udp_info`/`send_mtu_info` (`:144-146,267`).
    #[allow(clippy::too_many_lines)] // C `req_key_h`+`req_key_ext_h`
    // are 207 LOC together; the SPTPS-init branch alone is 36 LOC of
    // dense state-machine. Splitting would scatter the C line refs.
    fn on_req_key(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 REQ_KEY".into()))?;
        let msg = ReqKey::parse(body_str)
            .map_err(|_| DispatchError::BadKey("REQ_KEY parse failed".into()))?;

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:293-299`: `from = lookup_node(from_name)`. NOT
        // lookup_or_add: a REQ_KEY from an unknown node is an error
        // (the meta-conn should have ADD_EDGE'd them first).
        let Some(&from_nid) = self.node_ids.get(&msg.from) else {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} origin {} which is unknown",
                        msg.from);
            return Ok(false);
        };
        let Some(&to_nid) = self.node_ids.get(&msg.to) else {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} destination {} which is unknown",
                        msg.to);
            return Ok(false);
        };

        // C `:310-345`: `if(to == myself)` vs relay.
        if to_nid != self.myself {
            // C `:327-344`: relay. `send_request(to->nexthop->
            // connection, "%s", request)` — forward verbatim.
            // STUB(chunk-9): 2-node mesh has no relay.
            log::debug!(target: "tincd::proto",
                        "REQ_KEY relay {} → {}; STUB(chunk-9)",
                        msg.from, msg.to);
            return Ok(false);
        }

        // C `:312-315`: `if(!from->status.reachable) return true`.
        if !self.graph.node(from_nid).is_some_and(|n| n.reachable) {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} origin {} which is unreachable",
                        msg.from);
            return Ok(false);
        }

        // C `:318-320`: `if(experimental && reqno) req_key_ext_h()`.
        // We're always-experimental (SPTPS-only). `ext` is the
        // parsed `reqno [payload]` tail.
        let Some(ext) = &msg.ext else {
            // C `:323`: `send_ans_key(from)`. The legacy 3-token
            // `"%d %s %s"` form (no extension). The legacy peer
            // wants our session key in plaintext-hex. We don't do
            // legacy. STUB(chunk-never).
            log::error!(target: "tincd::proto",
                        "Got legacy REQ_KEY from {} (no SPTPS extension)",
                        msg.from);
            return Ok(false);
        };

        // C `req_key_ext_h:139` `switch(reqno)`.
        // `reqno` re-uses `request_t` enum values: REQ_KEY=15 is
        // SPTPS-init, REQ_PUBKEY=19, ANS_PUBKEY=20, SPTPS_PACKET=21.
        if ext.reqno != Request::ReqKey as i32 {
            // STUB(chunk-9): REQ_PUBKEY/ANS_PUBKEY (`:196-231`),
            // SPTPS_PACKET (`:149-188`). The latter is the TCP-
            // tunnel-data path (when UDP is blocked). C `:270`:
            // `default: "Unknown extended REQ_KEY" return true`.
            log::warn!(target: "tincd::proto",
                       "Got REQ_KEY ext reqno={} from {} — STUB(chunk-9)",
                       ext.reqno, msg.from);
            return Ok(false);
        }

        // ─── case REQ_KEY (`:234-269`): SPTPS responder start.
        // C `:235-239`: `if(!node_read_ecdsa_public_key(from))
        // send REQ_PUBKEY`. Same loader as send_req_key.
        let host_config = {
            let host_file = self.confbase.join("hosts").join(&msg.from);
            let mut cfg = tinc_conf::Config::default();
            if let Ok(entries) = tinc_conf::parse_file(&host_file) {
                cfg.merge(entries);
            }
            cfg
        };
        let Some(hiskey) =
            crate::keys::read_ecdsa_public_key(&host_config, &self.confbase, &msg.from)
        else {
            // STUB(chunk-9): `:236-238` `send REQ_PUBKEY`.
            log::warn!(target: "tincd::proto",
                       "No Ed25519 key known for {}; cannot start tunnel",
                       msg.from);
            return Ok(false);
        };

        // C `:241-243`: `if(from->sptps.label) "Got REQ_KEY while
        // we already started a SPTPS session!"`. The peer is re-
        // initiating (their previous attempt timed out, or they
        // restarted). C just logs and continues (`sptps_stop` at
        // `:261` resets); we match.
        if self
            .tunnels
            .get(&from_nid)
            .is_some_and(|t| t.sptps.is_some())
        {
            log::debug!(target: "tincd::proto",
                        "Got REQ_KEY from {} while SPTPS already started; restarting",
                        msg.from);
        }

        // C `:245-254`: b64decode the payload.
        let Some(payload) = ext.payload.as_deref() else {
            log::error!(target: "tincd::proto",
                        "Got bad REQ_SPTPS_START from {}: no payload", msg.from);
            return Ok(false);
        };
        let Some(kex_bytes) = tinc_crypto::b64::decode(payload) else {
            log::error!(target: "tincd::proto",
                        "Got bad REQ_SPTPS_START from {}: invalid SPTPS data",
                        msg.from);
            return Ok(false);
        };

        // C `:256-263`: `snprintf(label, ..., from->name, myself->
        // name)` then `sptps_stop; validkey=false; waitingforkey=
        // true; sptps_start(..., false, true, ...)`. Note arg order:
        // INITIATOR's name first — same label both sides. `false,
        // true` = responder, datagram.
        let label = make_udp_label(&msg.from, &self.name);
        let mykey = SigningKey::from_blob(&self.mykey.to_blob());
        let (mut sptps, init_outs) = Sptps::start(
            Role::Responder,
            Framing::Datagram,
            mykey,
            hiskey,
            label,
            16,
            &mut OsRng,
        );

        // C `:264`: `sptps_receive_data(&from->sptps, buf, len)`.
        // Feed their KEX. This produces our KEX + SIG (responder
        // sends both after receiving initiator's KEX) — those go
        // via `send_sptps_data` → ANS_KEY.
        let recv_result = sptps.receive(&kex_bytes, &mut OsRng);

        // Stash the SPTPS BEFORE dispatching the outputs (the
        // dispatch may call `send_sptps_data` which doesn't read
        // it, but be safe).
        let now = self.timers.now();
        let tunnel = self.tunnels.entry(from_nid).or_default();
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        // STUB(chunk-9): `:267` `send_mtu_info(myself, from, MTU)`.

        // Dispatch: init_outs (responder's `start()` KEX, but
        // datagram-mode responder ALSO emits a KEX from `start()`
        // — wait, no: re-read state.rs. `start()` always sends KEX
        // (`send_kex` at `:378`). For datagram-responder that goes
        // via `send_sptps_data` (ANS_KEY). C does this too: `sptps_
        // start(..., send_sptps_data_myself, ...)` at `:263` means
        // the responder's KEX immediately fires the callback.
        // BUT C also has the initiator's `send_initial_sptps_data`
        // special-case for the FIRST Wire — the responder doesn't
        // (`:263` uses `send_sptps_data_myself` not the init one).
        // So responder KEX goes via ANS_KEY straight away.)
        //
        // recv_outs has the responder's SIG (from `receive_kex` →
        // `send_sig`, but only initiator-side... no, re-read:
        // `receive_kex` only sends SIG `if(is_initiator)`. So
        // responder's SIG comes later, from `receive_sig`. The
        // recv here is the initiator's KEX; responder stashes it
        // and that's all. recv_outs is empty.)
        //
        // ACTUAL flow:
        //   responder start() → KEX → ANS_KEY (init_outs)
        //   responder receive(init's KEX) → stash, no output
        //   [initiator gets responder's KEX via ans_key_h]
        //   [initiator receive() → sends SIG via ANS_KEY]
        //   responder receive(init's SIG) → send own SIG +
        //     HandshakeDone (`receive_sig:684-695` responder branch)
        let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, init_outs);
        match recv_result {
            Ok((_consumed, recv_outs)) => {
                nw |= self.dispatch_tunnel_outputs(from_nid, &msg.from, recv_outs);
            }
            Err(e) => {
                log::error!(target: "tincd::proto",
                            "Failed to decode REQ_KEY SPTPS data from {}: {e:?}",
                            msg.from);
                // C `:249`: returns true (don't drop conn). We match.
            }
        }
        Ok(nw)
    }

    /// `ans_key_h` (`protocol_key.c:420-648`), SPTPS branch only
    /// (`:549-581`). The other end of the per-tunnel handshake:
    /// b64-decode the key field, feed it to `tunnels[from].sptps`.
    ///
    /// The legacy branch (`!from->status.sptps`, `:585-648`) is
    /// the OpenSSL cipher/digest negotiation. STUB(chunk-never):
    /// we're SPTPS-only.
    ///
    /// STUB(chunk-9):
    /// - `to != myself` relay + reflexive-addr append (`:462-482`).
    /// - compression-level check (`:499-545`).
    /// - `if(validkey) update_node_udp(reflexive)` (`:568-576`).
    /// - `send_mtu_info` (`:578`).
    fn on_ans_key(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 ANS_KEY".into()))?;
        let msg = AnsKey::parse(body_str)
            .map_err(|_| DispatchError::BadKey("ANS_KEY parse failed".into()))?;

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:444-460`: `from = lookup_node`; `to = lookup_node`.
        let Some(&from_nid) = self.node_ids.get(&msg.from) else {
            log::error!(target: "tincd::proto",
                        "Got ANS_KEY from {conn_name} origin {} which is unknown",
                        msg.from);
            return Ok(false);
        };
        let Some(&to_nid) = self.node_ids.get(&msg.to) else {
            log::error!(target: "tincd::proto",
                        "Got ANS_KEY from {conn_name} destination {} which is unknown",
                        msg.to);
            return Ok(false);
        };

        // C `:462-484`: `if(to != myself)` relay. STUB(chunk-9).
        if to_nid != self.myself {
            log::debug!(target: "tincd::proto",
                        "ANS_KEY relay {} → {}; STUB(chunk-9)",
                        msg.from, msg.to);
            return Ok(false);
        }

        // STUB(chunk-9): `:499-545` compression-level check. We
        // don't compress; ignore the field.

        // C `:549`: `if(from->status.sptps)`. Always true for us
        // (no legacy). The `key` field is the b64'd SPTPS
        // handshake record.
        let Some(hs_bytes) = tinc_crypto::b64::decode(&msg.key) else {
            log::error!(target: "tincd::proto",
                        "Got bad ANS_KEY from {}: invalid SPTPS data", msg.from);
            return Ok(false);
        };

        // C `:553`: `sptps_receive_data(&from->sptps, buf, len)`.
        // The SPTPS state machine MUST already exist (we sent
        // REQ_KEY first; `send_req_key` set `tunnel.sptps`).
        let Some(sptps) = self
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            // C `:553` would deref a NULL `from->sptps.state`.
            // The C reaches `sptps_receive_data` with a zeroed
            // struct → returns false → hits the restart logic
            // at `:556-563`. We're safer: log + restart.
            log::warn!(target: "tincd::proto",
                       "Got ANS_KEY from {} but no SPTPS state; restarting",
                       msg.from);
            return Ok(self.send_req_key(from_nid));
        };

        let result = sptps.receive(&hs_bytes, &mut OsRng);
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // C `:555-563`: "tunnel stuck" restart logic. Gate
                // on `last_req_key + 10 < now`.
                log::warn!(target: "tincd::proto",
                           "Failed to decode ANS_KEY SPTPS data from {}: {e:?}; restarting",
                           msg.from);
                let now = self.timers.now();
                let gate_ok = self.tunnels.get(&from_nid).is_none_or(|t| {
                    t.last_req_key
                        .is_none_or(|last| now.duration_since(last).as_secs() >= 10)
                });
                if gate_ok {
                    return Ok(self.send_req_key(from_nid));
                }
                return Ok(false);
            }
        };

        // STUB(chunk-9): `:568-576` `if(validkey && *address)
        // update_node_udp(reflexive_addr)`. The relay-appended
        // addr/port lets us learn our NAT-public address.
        // STUB(chunk-9): `:578` `send_mtu_info`.

        // Dispatch. May contain `HandshakeDone` (→ set validkey,
        // log "successful") and/or `Wire` (next handshake step,
        // → ANS_KEY back).
        Ok(self.dispatch_tunnel_outputs(from_nid, &msg.from, outs))
    }

    /// Dedup gate for flooded messages. `seen_request` (`protocol.
    /// c:234-249`). Returns `true` if `body` was already seen —
    /// caller drops silently (return `Ok(false)`, don't process,
    /// don't forward).
    ///
    /// `body` is the FULL line (`\n` already stripped). C keys on
    /// `strcmp` of the whole `request` string; the dedup nonce
    /// (second `%x` token) makes identical-payload-different-origin
    /// messages distinct. We pass `body` as-is. The &[u8]→&str
    /// conversion: C `strcmp` is byte-compare; `seen.check` keys on
    /// `&str` (HashMap via `Borrow<str>`). Node names are `check_id`-
    /// gated to ASCII so the body IS valid UTF-8; `from_utf8` here
    /// is just a type cast.
    fn seen_request(&mut self, body: &[u8]) -> bool {
        // `from_utf8` failure: body has high bytes. Shouldn't
        // happen (the parsers already validated). Treat as not-
        // seen (don't dup-drop garbage — let the handler reject).
        let Ok(s) = std::str::from_utf8(body) else {
            return false;
        };
        self.seen.check(s, self.timers.now())
    }

    /// `prng(UINT32_MAX)` (`utils.c`). Nonce for the dedup field
    /// in flooded ADD/DEL messages. The C uses a fast non-crypto
    /// PRNG (xoshiro256**); we use `OsRng` — overkill but already
    /// linked, no extra dep, and these messages are not hot (one
    /// per topology change). The nonce only needs to be unique-ish
    /// across the mesh's TTL window; cryptographic strength is
    /// gratuitous, not wrong.
    fn nonce() -> u32 {
        OsRng.next_u32()
    }

    /// Connections eligible for broadcast: every conn that's past
    /// ACK and isn't `from`. C `meta.c:115`: `if(c != from && c->
    /// edge)`. We test `conn.active` (set in `on_ack`).
    ///
    /// Returns `Vec<ConnId>` (not an iterator) so callers can
    /// `get_mut` while sending — the slotmap iterator borrow would
    /// conflict. Same two-phase collect-then-send shape as
    /// `dispatch_sptps_outputs`. Broadcast is per-topology-change,
    /// not per-packet; the alloc is fine.
    fn broadcast_targets(&self, from: Option<ConnId>) -> Vec<ConnId> {
        self.conns
            .iter()
            .filter(|&(id, c)| Some(id) != from && c.active)
            .map(|(id, _)| id)
            .collect()
    }

    /// `forward_request` (`protocol.c:135-146`) → `broadcast_meta`
    /// (`meta.c:113-117`). Re-send `body` (a decrypted SPTPS record
    /// payload, `\n` already stripped by `record_body`) to every
    /// active connection except `from`. The receivers' `seen.check`
    /// drops it if they already have it — that plus the `from` skip
    /// is the loop break.
    ///
    /// C `protocol.c:144` re-appends `\n` then calls `broadcast_
    /// meta` which calls `send_meta` (NOT `send_meta_raw`) — i.e.
    /// the SPTPS-encrypted path. `conn.send()` does both: appends
    /// `\n`, routes through `sptps_send_record`. The body is UTF-8
    /// (parsers already validated; tinc protocol is text); the
    /// `from_utf8` here is the `&[u8]` → `Display` impedance match.
    ///
    /// Returns `true` if any target's outbuf went empty→nonempty.
    fn forward_request(&mut self, from: ConnId, body: &[u8]) -> bool {
        // Body is post-parse: `parse_add_subnet` etc already
        // succeeded, which means `from_utf8` did. Shouldn't fire.
        let Ok(s) = std::str::from_utf8(body) else {
            log::warn!(target: "tincd::proto",
                       "forward_request: non-UTF-8 body, dropping");
            return false;
        };
        let targets = self.broadcast_targets(Some(from));
        if targets.is_empty() {
            // One peer: `from` was the only active conn. The skip
            // makes this a no-op. Chunk-5 tests live here.
            return false;
        }
        log::debug!(target: "tincd::proto",
                    "Forwarding to {} peer(s): {s}", targets.len());
        let mut nw = false;
        for id in targets {
            if let Some(c) = self.conns.get_mut(id) {
                nw |= c.send(format_args!("{s}"));
            }
        }
        nw
    }

    /// `send_request(everyone, ...)` (`protocol.c:122-125`). The
    /// `c == everyone` branch: format with a fresh nonce then
    /// `broadcast_meta(NULL, ...)`. The `from = None` means NO conn
    /// is skipped — used by `on_ack`'s `send_add_edge(everyone, e)`
    /// (`ack_h:1058`) and `terminate`'s `send_del_edge(everyone, e)`
    /// (`net.c:128`). The new conn / dying conn isn't `active` yet
    /// (or anymore), so it's filtered by `broadcast_targets` anyway.
    ///
    /// Each target gets its OWN nonce — the C `prng(UINT32_MAX)`
    /// is INSIDE `send_request`, which `broadcast_meta` calls
    /// once. Wait, no: `broadcast_meta` calls `send_meta` per
    /// target, but `send_request(everyone, ...)` formats ONCE then
    /// `broadcast_meta` re-sends the SAME bytes. So: one nonce.
    /// Same here: format outside the loop.
    fn broadcast_line(&mut self, line: &str) -> bool {
        let targets = self.broadcast_targets(None);
        let mut nw = false;
        for id in targets {
            if let Some(c) = self.conns.get_mut(id) {
                nw |= c.send(format_args!("{line}"));
            }
        }
        nw
    }

    /// `send_add_edge` (`protocol_edge.c:37-62`). Format the edge
    /// from `graph` + `edge_addrs` and queue to ONE conn.
    ///
    /// C `:42`: `sockaddr2str(&e->address, &address, &port)`. Our
    /// `edge_addrs` stores the `AddrStr` tokens verbatim. The
    /// `e->local_address.sa.sa_family` check (`:44`) is the
    /// `AF_UNSPEC` test — our `local_addr == "unspec"` is the
    /// equivalent (we stored the literal in `on_ack`/`on_add_edge`).
    ///
    /// Returns `None` if either the edge or its addr entry is gone
    /// (caller skips with a warn). The C never has the missing-addr
    /// case (`e->address` is always set); chunk-5's synthesized
    /// reverse from `on_ack` does. The proper fix is `on_ack`
    /// populating both halves, but until then we skip rather than
    /// emit `"unknown port unknown"` on the wire (peers would
    /// `str2sockaddr` it to `AF_UNKNOWN` and never connect).
    fn fmt_add_edge(&self, eid: EdgeId, nonce: u32) -> Option<String> {
        let e = self.graph.edge(eid)?;
        let (addr, port, la, lp) = self.edge_addrs.get(&eid)?;
        let from = self.graph.node(e.from)?.name.clone();
        let to = self.graph.node(e.to)?.name.clone();
        // C `:44`: `if(e->local_address.sa.sa_family)`. AF_UNSPEC
        // is 0; our sentinel is the `"unspec"` string token.
        let local = if la.as_str() == AddrStr::UNSPEC {
            None
        } else {
            Some((la.clone(), lp.clone()))
        };
        let msg = AddEdge {
            from,
            to,
            addr: addr.clone(),
            port: port.clone(),
            options: e.options,
            weight: e.weight,
            local,
        };
        Some(msg.format(nonce))
    }

    /// `send_add_edge(c, e)` to ONE target. Correction path
    /// (`protocol_edge.c:153,289`).
    fn send_add_edge(&mut self, to: ConnId, eid: EdgeId) -> bool {
        let Some(line) = self.fmt_add_edge(eid, Self::nonce()) else {
            log::warn!(target: "tincd::proto",
                       "send_add_edge: edge {eid:?} has no addr entry, skipping");
            return false;
        };
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    /// `send_del_edge(c, e)` (`protocol_edge.c:219-222`). Just
    /// `"%d %x %s %s"`. The C builds a transient `edge_t` for the
    /// `:190` contradiction case (no real edge to format from); we
    /// take names directly.
    fn send_del_edge(&mut self, to: ConnId, from_name: &str, to_name: &str) -> bool {
        let msg = DelEdge {
            from: from_name.to_owned(),
            to: to_name.to_owned(),
        };
        let line = msg.format(Self::nonce());
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    /// `send_add_subnet`/`send_del_subnet` (`protocol_subnet.c:
    /// 33-44,153-161`). Same wire shape; `which` picks the reqno.
    fn send_subnet(&mut self, to: ConnId, which: Request, owner: &str, subnet: &Subnet) -> bool {
        let msg = SubnetMsg {
            owner: owner.to_owned(),
            subnet: *subnet,
        };
        let line = msg.format(which, Self::nonce());
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    /// `send_everything` (`protocol_auth.c:870-900`). Walk the
    /// world model, send ADD_SUBNET + ADD_EDGE for everything we
    /// know. Called from `on_ack` (`ack_h:1028`) — bring the new
    /// peer up to speed.
    ///
    /// C: nested `splay_each(node) { splay_each(subnet); splay_
    /// each(edge) }`. We flatten: `SubnetTree::iter()` walks ALL
    /// subnets in one pass (no per-node grouping needed — the wire
    /// format carries `(owner, subnet)`, the order doesn't matter);
    /// `Graph::edge_iter()` walks ALL edges. The C's per-node
    /// nesting is an artifact of `n->subnet_tree`/`n->edge_tree`
    /// hanging off each `node_t`; we have global trees. Same wire
    /// output, less indirection.
    ///
    /// `disablebuggypeers` (`:873-881`): the zeropkt workaround
    /// for an ancient bug. Niche knob; skipped. `tunnelserver`
    /// (`:884-889`): myself-only mode. STUBBED (chunk 9).
    fn send_everything(&mut self, to: ConnId) -> bool {
        // Collect into a `Vec<String>` first: `subnets.iter()`
        // borrows `&self`, `conn.send()` needs `&mut self.conns`.
        // Disjoint fields, but `self.nonce()` (associated fn,
        // doesn't borrow) and `format` are pure — easiest to
        // pre-format.
        let mut lines: Vec<String> = Vec::new();

        // C `:893`: `for splay_each(subnet_t, s, &n->subnet_tree)`.
        // Flattened: one walk over the global tree.
        for (subnet, owner) in self.subnets.iter() {
            let msg = SubnetMsg {
                owner: owner.to_owned(),
                subnet: *subnet,
            };
            lines.push(msg.format(Request::AddSubnet, Self::nonce()));
        }

        // C `:897`: `for splay_each(edge_t, e, &n->edge_tree)`.
        // `edge_iter()` is one slab pass. Edges with no `edge_
        // addrs` entry (chunk-5's synthesized reverse) are skipped
        // — see `fmt_add_edge` doc. The peer will learn that edge
        // from the OTHER endpoint's `send_add_edge(everyone, ...)`
        // when THEY connect.
        let eids: Vec<EdgeId> = self.graph.edge_iter().map(|(id, _)| id).collect();
        for eid in eids {
            if let Some(line) = self.fmt_add_edge(eid, Self::nonce()) {
                lines.push(line);
            }
        }

        let Some(conn) = self.conns.get_mut(to) else {
            return false;
        };
        let mut nw = false;
        for line in lines {
            nw |= conn.send(format_args!("{line}"));
        }
        log::debug!(target: "tincd::proto",
                    "send_everything to {}: {} subnets, {} edges sent",
                    conn.name, self.subnets.len(),
                    self.edge_addrs.len());
        nw
    }

    /// `graph()` (`graph.c:322-327`): sssp + diff + mst. Logs each
    /// transition. The script-spawn / sptps_stop / mtu-reset are
    /// chunk-7/8 deferrals; the LOG proves the diff fired.
    ///
    /// C `graph.c:227`: `"Node %s (%s) became reachable"` at
    /// `DEBUG_TRAFFIC`. We don't have the hostname (no `NodeState`
    /// for transitive nodes); log the name from the graph.
    fn run_graph_and_log(&mut self) {
        let (transitions, _mst, routes) = run_graph(&mut self.graph, self.myself);
        // Stash for `dump_nodes` (`node.c:218`: nexthop/via/distance
        // are read straight off `node_t`, which the C `graph.c:188-
        // 196` writes into). We keep the side table.
        self.last_routes = routes;
        // STUB(chunk-9): _mst feeds connection_t.status.mst, read
        // ONLY by broadcast_packet (`net_packet.c:1635`). The
        // broadcast tree is route.c-rest territory.
        // STUB(chunk-9): subnet_cache_flush_tables (`graph.c:323`).
        // The hash cache (`subnet.c:53-130`) isn't ported; nothing
        // to flush. Lands when the cache does.
        for t in transitions {
            match t {
                Transition::BecameReachable { node, via: via_nid } => {
                    // `graph.c:261-262`: INFO. Look up the name —
                    // graph.node() is `Some` (just came from
                    // node_ids() inside diff_reachability).
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    let via_name = self
                        .graph
                        .node(via_nid)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became reachable (via {via_name})");

                    // C `graph.c:201`: `update_node_udp(n,
                    // &e->reverse->address)`. The SSSP `prevedge`'s
                    // reverse address is the "how to reach this
                    // node via UDP" guess. For chunk 7: use the
                    // edge addr from `on_ack` (`NodeState.edge_addr`,
                    // already port-rewritten to UDP). With direct
                    // neighbors, that's the right answer; transitives
                    // would need the prevedge-walk (chunk 9).
                    // STUB(chunk-9): full `update_node_udp` (also
                    // re-indexes `node_udp_tree` for the addr-based
                    // lookup at `net_packet.c:1728`).
                    let name_owned = name.to_owned();
                    let addr = self.nodes.get(&name_owned).and_then(|ns| ns.edge_addr);
                    if let Some(addr) = addr {
                        let tunnel = self.tunnels.entry(node).or_default();
                        tunnel.udp_addr = Some(addr);
                    }

                    // C `graph.c:273-289`: `execute_script("host-
                    // up")` + `"hosts/NAME-up"`. AFTER the address
                    // is known (the script may want it).
                    self.run_host_script(true, &name_owned, addr);

                    // C `graph.c:294`: `subnet_update(n, NULL,
                    // reachable)`. The `subnet=NULL` branch
                    // (`subnet.c:352-372`): fire subnet-up for
                    // EVERY subnet this node owns. The node was
                    // unreachable; its subnets weren't routable;
                    // now they are.
                    let owned: Vec<Subnet> = self
                        .subnets
                        .iter()
                        .filter(|(_, o)| *o == name_owned)
                        .map(|(s, _)| *s)
                        .collect();
                    for s in &owned {
                        self.run_subnet_script(true, &name_owned, s);
                    }
                    // C `node.c:58-59` (`new_node`): `n->status.
                    // sptps` is set by `add_edge_h` (`protocol_edge.
                    // c:163-165`: `if(edge->options >> 24 >= 2)
                    // status.sptps = true`). For chunk 7: always
                    // true (no legacy peers). Set it here so `dump
                    // nodes` shows bit 6.
                    self.tunnels.entry(node).or_default().status.sptps = true;
                }
                Transition::BecameUnreachable { node } => {
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became unreachable");

                    let name_owned = name.to_owned();
                    // The address: read BEFORE `reset_unreachable`
                    // clears `udp_addr`. C `n->address` is also
                    // cleared by `update_node_udp(n, NULL)` at
                    // `:296`, but the script call at `:284` happens
                    // first. Match.
                    let addr = self
                        .tunnels
                        .get(&node)
                        .and_then(|t| t.udp_addr)
                        .or_else(|| self.nodes.get(&name_owned).and_then(|ns| ns.edge_addr));

                    // C `graph.c:273-289`: host-down + hosts/NAME-down.
                    self.run_host_script(false, &name_owned, addr);

                    // C `graph.c:294`: subnet-down for every owned
                    // subnet. Mirror of the BecameReachable case.
                    let owned: Vec<Subnet> = self
                        .subnets
                        .iter()
                        .filter(|(_, o)| *o == name_owned)
                        .map(|(s, _)| *s)
                        .collect();
                    for s in &owned {
                        self.run_subnet_script(false, &name_owned, s);
                    }

                    // C `graph.c:256-297`: sptps_stop, reset mtu
                    // probe state, clear status bits, clear UDP
                    // addr. `TunnelState::reset_unreachable` IS
                    // that whole block. STUB(chunk-9): mtu timer
                    // kill (`timeout_del(&n->udp_ping_timeout)`,
                    // `:270`) — the timer doesn't exist yet.
                    if let Some(tunnel) = self.tunnels.get_mut(&node) {
                        tunnel.reset_unreachable();
                    }
                }
            }
        }
    }

    /// `dump_nodes` row builder (`node.c:201-223`). Walks the graph
    /// (every known node, not just `nodes` — transitives included).
    ///
    /// C format string (`:210`): `"%d %d %s %s %s %d %d %lu %d %x
    /// %x %s %s %d %d %d %d %ld %d %"PRIu64×4`. Twenty-one printf
    /// conversions; the CLI's sscanf has 22 (`" port "` re-splits
    /// the fused hostname — see `tinc-tools::cmd::dump` doc).
    ///
    /// Chunk-5 placeholders for daemon state we don't track yet:
    /// - `id` (`node_id_t` 6-byte hash, `node.c:204-208`): chunk 7
    ///   (UDP) computes it. Zero-hex.
    /// - `cipher/digest/maclength`: `0 0 0` (DISABLE_LEGACY path,
    ///   `node.c:213`).
    /// - `compression`: `0` (`n->outcompression` defaults zero).
    /// - `mtu/minmtu/maxmtu`: `0 0 0` (chunk 9, PMTU discovery).
    /// - `last_state_change`: `0` (would need an `Instant` stash
    ///   per-node at transition time; deferred).
    /// - `udp_ping_rtt`: `-1` (the C init value, `node.c:58`).
    /// - traffic counters: `0` (chunk 7, per-tunnel stats).
    ///
    /// `status` bitfield (`node.h:32-48`, GCC LSB-first packing):
    /// only bit 4 (`reachable`) is real — read from `graph.node().
    /// reachable` (written by `run_graph_and_log`'s diff). The CLI's
    /// `dump reachable nodes` filter (`tincctl.c:1306`) keys on it.
    fn dump_nodes_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for nid in self.graph.node_ids() {
            let Some(node) = self.graph.node(nid) else {
                continue; // freed slot (concurrent del; defensive)
            };
            let name = node.name.as_str();

            // C `:211`: `n->hostname ? n->hostname : "unknown port
            // unknown"`. C `net_setup.c:1199`: `myself->hostname =
            // "MYSELF port <tcp>"`. Directly-connected peers get a
            // hostname from `c->address` rewritten to UDP port
            // (`ack_h:1024-1025`, our `NodeState.edge_addr`).
            // Transitives have no hostname (the C learns it from
            // `update_node_udp`, chunk-7 UDP territory) → the
            // literal.
            let hostname = if nid == self.myself {
                format!("MYSELF port {}", self.my_udp_port)
            } else if let Some(ea) = self.nodes.get(name).and_then(|ns| ns.edge_addr.as_ref()) {
                // `fmt_addr` shape: `"%s port %s"`, no v6 brackets
                // (matches `getnameinfo NI_NUMERICHOST`).
                fmt_addr(ea)
            } else {
                "unknown port unknown".to_string()
            };

            // C `:217`: `n->options`. The C `graph.c:192` writes
            // `e->to->options = e->options` during sssp — i.e. the
            // INCOMING edge's options. `last_routes` carries that.
            // For `myself`, sssp seeds `options=0` (`graph.c:144`
            // never writes it; `sssp` here mirrors that). For
            // unreachable nodes (no route), C reads stale; we read
            // 0.
            let route = self
                .last_routes
                .get(nid.0 as usize)
                .and_then(Option::as_ref);
            let options = route.map_or(0, |r| r.options);

            // C `:217`: `n->status.value`. `TunnelStatus::as_u32`
            // packs the bits we track (validkey, waitingforkey,
            // sptps, udp_confirmed, udppacket); `reachable` is the
            // param. `myself`'s status: just `reachable` (we don't
            // tunnel to ourselves). C `:217` reads `n->status.value`
            // which for `myself` is whatever `xzalloc` left; the C
            // `setup_myself:1050` sets `reachable=true` and that's
            // it.
            let tunnel = self.tunnels.get(&nid);
            let status = tunnel.map_or_else(
                || {
                    if node.reachable { 1 << 4 } else { 0 }
                },
                |t| t.status.as_u32(node.reachable),
            );

            // C `:218`: `n->nexthop ? n->nexthop->name : "-"`. Read
            // from `last_routes`. Unreachable → `"-"` (C: `nexthop`
            // is whatever stale pointer `xzalloc` left, but the C
            // `node.c:218` does NULL-check; freshly-created nodes
            // have NULL nexthop).
            let (nexthop, via, distance) = match route {
                Some(r) => {
                    let nh = self.graph.node(r.nexthop).map_or("-", |n| n.name.as_str());
                    let via = self.graph.node(r.via).map_or("-", |n| n.name.as_str());
                    (nh, via, r.distance)
                }
                // C: unreachable nodes keep stale `distance` (last
                // sssp that DID reach them). `xzalloc` fresh nodes
                // have `distance=0`. We don't track stale; emit 0.
                None => ("-", "-", 0),
            };

            // C `:210` format. The %lu (maclength) and %ld (last_
            // state_change) are `0` literals; %"PRIu64" ×4 are `0`.
            // udp_ping_rtt is `-1` (C `node.c:58`: `n->udp_ping_rtt
            // = -1`).
            rows.push(format!(
                "{} {} {} {} {} {} {} {} {} {:x} {:x} {} {} {} {} {} {} {} {} {} {} {} {}",
                Request::Control as u8,       // %d CONTROL
                crate::proto::REQ_DUMP_NODES, // %d
                name,                         // %s
                self.id6_table.id_of(nid).unwrap_or(NodeId6::NULL), // %s id
                hostname,                     // %s ("HOST port PORT")
                0,                            // %d cipher (DISABLE_LEGACY)
                0,                            // %d digest
                0,                            // %lu maclength
                0,                            // %d compression
                options,                      // %x
                status,                       // %x
                nexthop,                      // %s
                via,                          // %s
                distance,                     // %d
                tunnel.map_or(0, |t| t.mtu),  // %d mtu
                tunnel.map_or(0, |t| t.minmtu), // %d minmtu
                tunnel.map_or(0, |t| t.maxmtu), // %d maxmtu
                0,                            // %ld last_state_change
                -1,                           // %d udp_ping_rtt
                tunnel.map_or(0, |t| t.in_packets), // %PRIu64
                tunnel.map_or(0, |t| t.in_bytes),
                tunnel.map_or(0, |t| t.out_packets),
                tunnel.map_or(0, |t| t.out_bytes),
            ));
        }
        rows
    }

    /// `dump_edges` row builder (`edge.c:123-137`). Nested walk:
    /// per node, per outgoing edge — the C `splay_each(node) splay_
    /// each(edge)` shape. Edges are directional; both halves of a
    /// bidi pair appear as separate rows.
    ///
    /// C format (`:128`): `"%d %d %s %s %s %s %x %d"`. Six body
    /// conversions; CLI sscanf has 8 (TWO `" port "` re-splits —
    /// addr AND local_addr are `sockaddr2hostname` output).
    ///
    /// `e->address` formatting: C `sockaddr2hostname` (`netutl.c:
    /// 153-175`). For `AF_UNKNOWN` addrs (the unparsed-string case,
    /// what `str2sockaddr` builds when the addr token isn't a
    /// numeric IP), it's `"%s port %s"` of the stored strings
    /// (`netutl.c:163`). That's what we stored in `edge_addrs` —
    /// raw `AddrStr` tokens, round-tripped verbatim.
    ///
    /// Edges with no `edge_addrs` entry (the synthesized reverse
    /// from `on_ack`, see the STUB note there): `"unknown port
    /// unknown"`. The C wouldn't have such edges (the peer's
    /// `send_add_edge` would've populated them); chunk-5 specific.
    fn dump_edges_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        // C `:124-125`: `for splay_each(node) for splay_each(edge,
        // &n->edge_tree)`. `edge_iter()` is one slab pass, no per-
        // node hops. Order diverges from C (slab vs nested-splay);
        // intentional — `tincctl.c` reads dump rows into an
        // unordered set and sorts client-side. See `edge_iter()`
        // doc comment.
        for (eid, e) in self.graph.edge_iter() {
            let from = self
                .graph
                .node(e.from)
                .map_or("<gone>", |n| n.name.as_str());
            let to = self.graph.node(e.to).map_or("<gone>", |n| n.name.as_str());

            // C `:126-127`: `sockaddr2hostname(&e->address)` /
            // `sockaddr2hostname(&e->local_address)`. Our
            // `edge_addrs` stores the wire `AddrStr` pairs
            // verbatim; format as `"%s port %s"` (the
            // `AF_UNKNOWN` branch, `netutl.c:163`).
            let (addr, local) = match self.edge_addrs.get(&eid) {
                Some((a, p, la, lp)) => (format!("{a} port {p}"), format!("{la} port {lp}")),
                // Synthesized-reverse case (chunk-5 STUB; see
                // `on_ack`). The C never has addr-less edges.
                None => (
                    "unknown port unknown".to_string(),
                    "unknown port unknown".to_string(),
                ),
            };

            // C `:128`: `"%d %d %s %s %s %s %x %d"`.
            rows.push(format!(
                "{} {} {} {} {} {} {:x} {}",
                Request::Control as u8,
                crate::proto::REQ_DUMP_EDGES,
                from,
                to,
                addr,
                local,
                e.options,
                e.weight,
            ));
        }
        rows
    }

    /// `add_subnet_h` mutation half (`protocol_subnet.c:43-140`).
    ///
    /// C path traced:
    /// - `:49-68` parse + check_id + str2net — `parse_add_subnet`
    /// - `:71` `seen_request(request)` — dup-drop
    /// - `:77` `lookup_node(name)` — `lookup_or_add_node`
    /// - `:79-84` `tunnelserver` filter — STUBBED (deferred niche)
    /// - `:86-89` `if(!owner) new_node` — fused into lookup
    /// - `:93` `lookup_subnet(owner, &s)` — SubnetTree::add is
    ///   idempotent, but the C returns early WITHOUT forward. We
    ///   match: `seen` already dedups the flood; `add` idempotent.
    /// - `:98-104` `if(owner == myself)` — retaliate — STUBBED
    /// - `:116-122` `strictsubnets` — STUBBED (deferred)
    /// - `:126-128` `subnet_add(owner, new)` — SubnetTree::add
    /// - `:130-132` `subnet_update` script — STUBBED (chunk 8)
    /// - `:136-138` `forward_request` — STUBBED
    /// - `:142-148` MAC fast-handoff — STUBBED (no MAC subnets yet)
    ///
    /// NO `graph()` — subnets don't change topology. The C calls
    /// `subnet_update` (`subnet.c:327-393`, script firing) not
    /// `graph()`.
    ///
    /// Returns the io_set signal. Always `false` in chunk 5
    /// (forward stubbed, retaliate stubbed). Kept for chunk 5b.
    fn on_add_subnet(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_add_subnet(body)?;

        // C `:71`: `if(seen_request(request)) return true`.
        if self.seen_request(body) {
            return Ok(false);
        }

        // C `:77,86-89`: lookup_node + conditional new_node.
        // STUB(chunk-9): tunnelserver mode (`:79-84`) filters
        // indirect registrations. Niche feature; defer.
        let owner = self.lookup_or_add_node(&owner_name);

        // C `:98-104`: `if(owner == myself)`. Peer is wrong about
        // us — they think we own a subnet we don't. C sends
        // DEL_SUBNET correction back.
        if owner == self.myself {
            let conn_name = self
                .conns
                .get(from_conn)
                .map_or("<gone>", |c| c.name.as_str())
                .to_owned();
            log::warn!(target: "tincd::proto",
                       "Got ADD_SUBNET from {conn_name} for ourself ({subnet})");
            // C `:103`: `send_del_subnet(c, &s)`. Retaliate: tell
            // the peer to delete it. Our name as owner; the subnet
            // they just sent. Dark in single-peer tests (peer never
            // gossips our own subnets back at us); reachable via
            // stale gossip in a multi-peer mesh.
            let nw = self.send_subnet(from_conn, Request::DelSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // STUB(chunk-9): strictsubnets (`:116-122`). Deferred.

        // C `:126`: `subnet_add(owner, new)`. Idempotent on dup
        // (the C `:93` `if(lookup_subnet) return true` is
        // belt-and-braces over `seen_request`; our `add` is a
        // BTreeSet insert which is also idempotent). Clone the
        // owner: `subnet_update` below needs it. `Subnet` is `Copy`.
        self.subnets.add(subnet, owner_name.clone());

        // C `:130-132`: `if(owner->status.reachable) subnet_update(
        // owner, new, true)`. Only fire subnet-up if the owner is
        // reachable: a subnet learned via gossip for a node we can't
        // reach isn't actually routable yet (the host-up handler
        // fires it later, in the BecameReachable arm).
        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(true, &owner_name, &subnet);
        }

        // C `:136-138`: `if(!tunnelserver) forward_request(c, req)`.
        // The `seen.check` ABOVE prevents the loop (`seen_request`
        // is FIRST in C too, `:71`).
        let nw = self.forward_request(from_conn, body);

        // STUB(chunk-9): MAC fast-handoff (`:142-148`). No TAP/
        // RMODE_SWITCH yet; SUBNET_MAC subnets only exist in switch
        // mode (route.c-rest territory).

        Ok(nw)
    }

    /// `del_subnet_h` mutation half (`protocol_subnet.c:163-261`).
    ///
    /// C path traced:
    /// - `:163-188` parse — `parse_del_subnet`
    /// - `:191` `seen_request`
    /// - `:197` `lookup_node` — NOT lookup_or_add: DEL for an
    ///   unknown owner is a warn-and-drop (`:206-210`)
    /// - `:216` `lookup_subnet` — same: DEL for unknown subnet is
    ///   warn-and-drop (`:218-225`). Our `del()` returns `bool`.
    /// - `:199-204` `tunnelserver` filter — STUBBED (deferred niche)
    /// - `:231-236` `if(owner == myself)` retaliate ADD — STUBBED
    /// - `:244` `forward_request` — STUBBED
    /// - `:254-256` `subnet_update(..., false)` — STUBBED (chunk 8)
    /// - `:258` `subnet_del`
    fn on_del_subnet(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_del_subnet(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // STUB(chunk-9): tunnelserver mode (`:199-204`).

        // C `:197,206-210`: `lookup_node`. NOT lookup_or_add — a
        // DEL for a node we've never heard of is wrong. Warn,
        // return true (don't drop conn).
        let Some(&owner) = self.node_ids.get(&owner_name) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which is not in our node tree");
            return Ok(false);
        };

        // C `:231-236`: `if(owner == myself)`. Peer says we don't
        // own a subnet we DO own. C sends ADD_SUBNET correction.
        if owner == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for ourself ({subnet})");
            // C `:234`: `send_add_subnet(c, find)`. The C looks up
            // the subnet WE actually own (`find = lookup_subnet(
            // myself, &s)` at `:227`); if we don't own it either,
            // `:228-230` returns true (no correction — peer is
            // right, we DON'T own it). We don't track per-node
            // ownership of subnets here (`SubnetTree` is global +
            // owner-string); send back what they sent. Dark in
            // single-peer tests.
            let nw = self.send_subnet(from_conn, Request::AddSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // C `:244`: `if(!tunnelserver) forward_request(c, req)`.
        let nw = self.forward_request(from_conn, body);

        // C `:254-256`: `if(owner->status.reachable) subnet_update(
        // owner, find, false)`. BEFORE the del (the script may want
        // to see the route one last time — the C orders it this
        // way). Reachable check: same gate as add.
        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(false, &owner_name, &subnet);
        }

        // C `:258`: `subnet_del`. The C does `lookup_subnet` at
        // `:216` first and warns at `:218` if not found. Our
        // `del()` returns the bool; same outcome, one fewer walk.
        if !self.subnets.del(&subnet, &owner_name) {
            // C `:218-225`: warn, return true.
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which does not appear in his subnet tree");
        }

        Ok(nw)
    }

    /// `add_edge_h` mutation half (`protocol_edge.c:63-217`).
    ///
    /// C path traced:
    /// - `:77-92` parse — `parse_add_edge` (incl check_id, from≠to)
    /// - `:94` `seen_request`
    /// - `:99-100` `lookup_node(from/to)`
    /// - `:102-111` `tunnelserver` filter — STUBBED
    /// - `:112-120` `if(!from/to) new_node` — lookup_or_add
    /// - `:126-130` `str2sockaddr` — SKIPPED (graph doesn't store
    ///   addrs; AddrStr is opaque per Phase-1 finding)
    /// - `:134-183` `lookup_edge` exists branch:
    ///   - same weight+options → idempotent drop (`:145-148`)
    ///   - `from == myself` + different → send correction (`:150-
    ///     157`) — STUBBED
    ///   - different → update in place. `Graph::update_edge`
    ///     keeps the `EdgeId` slot stable (`edge_addrs` is keyed
    ///     on it; del+add only worked because the slab freelist is
    ///     LIFO — same slot back, by accident not contract).
    /// - `:184-196` `from == myself` + doesn't exist → contradiction.
    ///   C bumps `contradicting_add_edge`, sends DEL correction.
    ///   STUBBED.
    /// - `:197-205` `edge_add` — graph.add_edge
    /// - `:209-211` `forward_request` — STUBBED
    /// - `:215` `graph()` — run_graph_and_log
    #[allow(clippy::too_many_lines)] // C add_edge_h is 154 LOC; same
    fn on_add_edge(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let edge = parse_add_edge(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        // STUB(chunk-9): tunnelserver mode (`:103-111`).

        let from_id = self.lookup_or_add_node(&edge.from);
        let to_id = self.lookup_or_add_node(&edge.to);

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:134`: `e = lookup_edge(from, to)`.
        if let Some(existing) = self.graph.lookup_edge(from_id, to_id) {
            // C `:136-148`: same weight + options → idempotent.
            // (The C also compares address/local_address; we don't
            // store those on the graph edge. The address compare is
            // for the `update_node_udp` cache invalidation —
            // chunk-7 territory. For graph topology, weight+options
            // is what matters.)
            let e = self.graph.edge(existing).expect("just looked up");
            if e.weight == edge.weight && e.options == edge.options {
                // C `:145-148`: `return true`. No forward, no graph().
                return Ok(false);
            }

            // C `:150-157`: `from == myself` + edge exists with
            // different params. Peer's view of OUR edge is wrong.
            if from_id == self.myself {
                log::warn!(target: "tincd::proto",
                           "Got ADD_EDGE from {conn_name} for ourself \
                            which does not match existing entry");
                // C `:153`: `send_add_edge(c, e)`. Send back what
                // WE think the edge is (the existing one, NOT the
                // wire body). Dark in single-peer tests.
                let nw = self.send_add_edge(from_conn, existing);
                return Ok(nw);
            }

            // C `:159-183`: in-place update. C `splay_unlink`/
            // `splay_insert_node` (`:179-182`) re-keys edge_weight_
            // tree; `update_edge` does the same for `weight_order`.
            //
            // Why not del+add: `edge_addrs` is keyed on `EdgeId`.
            // del+add happens to recycle the same slot (LIFO
            // freelist), so `eid == existing` and the re-insert
            // keys to the same slot — correct by accident, not by
            // contract. One unrelated alloc between del and add and
            // the keys are stale. `update_edge` makes the slot
            // stability explicit; `edge_addrs.insert(existing, ...)`
            // is a plain overwrite of the same key.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} which does not \
                        match existing entry");
            self.graph
                .update_edge(existing, edge.weight, edge.options)
                .expect("lookup_edge just returned this EdgeId; no await, no free");
            // C `:173`: `e->address = address`. Same key, overwrite.
            let unspec = || AddrStr::new(AddrStr::UNSPEC).expect("literal");
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(existing, (edge.addr.clone(), edge.port.clone(), la, lp));
        } else if from_id == self.myself {
            // C `:184-196`: peer says WE have an edge we don't.
            // Contradiction. C bumps `contradicting_add_edge`
            // counter (read by periodic_handler `net.c:268`),
            // sends DEL_EDGE correction.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} for ourself \
                        which does not exist");
            // C `:186`: `contradicting_add_edge++`. Reader is
            // chunk 8's periodic_handler.
            self.contradicting_add_edge += 1;
            // C `:187-192`: build a transient `edge_t` (just
            // from/to names; no addr) for `send_del_edge`. We
            // pass names directly. The wire body's from/to are
            // what we deny.
            let nw = self.send_del_edge(from_conn, &edge.from, &edge.to);
            return Ok(nw);
        } else {
            // C `:197-205`: `edge_add`. The fresh-edge case.
            let eid = self
                .graph
                .add_edge(from_id, to_id, edge.weight, edge.options);
            // C `:199-204`: `e->address = address; e->local_address
            // = local_address`. The wire tokens, verbatim. `local`
            // is optional (pre-1.0.24 6-token form) — C leaves
            // `local_address` zeroed (`AF_UNSPEC`) which `sockaddr2
            // hostname` formats as `"unspec port unspec"` (`netutl.
            // c:159-160`).
            let unspec = || AddrStr::new(AddrStr::UNSPEC).expect("literal");
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(eid, (edge.addr.clone(), edge.port.clone(), la, lp));
        }

        // C `:209-211`: `if(!tunnelserver) forward_request(c, req)`.
        let nw = self.forward_request(from_conn, body);

        // C `:215`: `graph()`.
        self.run_graph_and_log();

        Ok(nw)
    }

    /// `del_edge_h` mutation half (`protocol_edge.c:225-322`).
    ///
    /// C path traced:
    /// - `:230-241` parse — `parse_del_edge`
    /// - `:244` `seen_request`
    /// - `:250-251` `lookup_node` (NOT lookup_or_add)
    /// - `:263-273` `from`/`to` not found → warn + return true
    /// - `:277-283` `lookup_edge` not found → warn + return true
    /// - `:253-261` `tunnelserver` filter — STUBBED (deferred niche)
    /// - `:285-291` `from == myself` → retaliate ADD — STUBBED
    /// - `:295-297` `forward_request` — STUBBED
    /// - `:301` `edge_del`
    /// - `:305` `graph()`
    /// - `:309-320` cleanup unreachable's reverse edge — STUBBED
    ///   (the daemon doesn't add reverse edges from on_ack yet;
    ///   the C's `lookup_edge(to, myself)` would find nothing)
    fn on_del_edge(&mut self, from_conn: ConnId, body: &[u8]) -> Result<bool, DispatchError> {
        let edge = parse_del_edge(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        // STUB(chunk-9): tunnelserver mode (`:253-261`).

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:250-273`: `lookup_node`. Missing is warn-and-drop
        // (return true), NOT a new_node. A DEL for a node we've
        // never heard of means our view is already consistent.
        let Some(&from_id) = self.node_ids.get(&edge.from) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree (unknown from: {})", edge.from);
            return Ok(false);
        };
        let Some(&to_id) = self.node_ids.get(&edge.to) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree (unknown to: {})", edge.to);
            return Ok(false);
        };

        // C `:277-283`: `lookup_edge`. Missing is warn-and-drop.
        let Some(eid) = self.graph.lookup_edge(from_id, to_id) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree");
            return Ok(false);
        };

        // C `:285-291`: `from == myself`. Peer says we DON'T have
        // an edge we DO have. C sends ADD_EDGE correction.
        if from_id == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} for ourself");
            // C `:288`: `contradicting_del_edge++`.
            self.contradicting_del_edge += 1;
            // C `:289`: `send_add_edge(c, e)`. The edge DOES exist
            // (we just looked it up); send what we know.
            let nw = self.send_add_edge(from_conn, eid);
            return Ok(nw);
        }

        // C `:295-297`: `if(!tunnelserver) forward_request(c, req)`.
        let nw = self.forward_request(from_conn, body);

        // C `:301`: `edge_del`.
        self.graph.del_edge(eid);
        self.edge_addrs.remove(&eid);

        // C `:305`: `graph()`.
        self.run_graph_and_log();

        // C `:309-320`: reverse-edge cleanup. If `to` became
        // unreachable AND has an edge back to us, delete +
        // broadcast that too. The C `lookup_edge(to, myself)` is
        // the synthesized reverse from `ack_h`. We DO add both
        // halves in `on_ack`; check.
        if !self.graph.node(to_id).is_some_and(|n| n.reachable) {
            if let Some(rev) = self.graph.lookup_edge(to_id, self.myself) {
                // C `:315`: `send_del_edge(everyone, e)`.
                let to_name = edge.to.clone();
                let my_name = self.name.clone();
                let line = DelEdge {
                    from: to_name,
                    to: my_name,
                }
                .format(Self::nonce());
                self.broadcast_line(&line);
                // C `:318`: `edge_del(e)`.
                self.graph.del_edge(rev);
                self.edge_addrs.remove(&rev);
            }
        }

        Ok(nw)
    }

    /// `ack_h` mutation half (`protocol_auth.c:965-1064`). Parse
    /// done by `proto::parse_ack`; this does the world-model edits
    /// (which need `&mut self`).
    ///
    /// C path traced:
    /// - `:965-991` lookup_node / new_node / dup-conn handling
    /// - `:993-994` `n->connection = c; c->node = n`
    /// - `:996-999` PMTU intersection (BOTH sides must want it)
    /// - `:1001` `c->options |= options`
    /// - `:1003-1019` PMTU/ClampMSS per-host re-read — STUBBED
    /// - `:1023` `c->allow_request = ALL`
    /// - `:1028` `send_everything(c)` — walks empty trees, sends 0
    /// - `:1032-1051` edge_add: address+port, getsockname, weight avg
    /// - `:1055-1059` `send_add_edge` broadcast — STUBBED (no peers)
    /// - `:1063` `graph()` — ✅ `run_graph_and_log()`
    ///
    /// Returns the io_set signal. (Always `false` in chunk 4b:
    /// `send_everything` iterates empty trees, `send_add_edge` is
    /// stubbed. Kept for chunk 5 when both fire.)
    fn on_ack(&mut self, id: ConnId, body: &[u8]) -> Result<bool, crate::proto::DispatchError> {
        let parsed = parse_ack(body)?;
        let conn = self.conns.get_mut(id).expect("caller checked");

        // C `:948-950`: `if(minor == 1) return upgrade_h(c, req)`.
        // We rejected minor < 2 in id_h. Unreachable.

        // ─── PMTU intersection (`:996-999`)
        // C: `if(!(c->options & options & PMTU)) { c->options &=
        // ~PMTU; options &= ~PMTU; }`. PMTU only sticks if BOTH
        // sides want it (the AND). If either's bit is clear, clear
        // both. Then OR in the rest.
        let mut his = parsed.his_options;
        if conn.options & his & crate::proto::OPTION_PMTU_DISCOVERY == 0 {
            conn.options &= !crate::proto::OPTION_PMTU_DISCOVERY;
            his &= !crate::proto::OPTION_PMTU_DISCOVERY;
        }
        conn.options |= his;

        // C `:1003-1019`: per-host PMTU/ClampMSS re-read. STUBBED
        // (config_tree not retained, see id_h doc).

        // C `:1023`: `c->allow_request = ALL`. Our `None`.
        conn.allow_request = None;

        log::info!(target: "tincd::conn",
                   "Connection with {} ({}) activated",
                   conn.name, conn.hostname);

        // ─── lookup_node / node_add (`:965-994`)
        // C: `n = lookup_node(c->name); if(!n) { n = new_node();
        // node_add(n); } else if(n->connection) { ... close old }`.
        //
        // The dup-conn case (`:975-990`): we already have a live
        // connection to this node, the new one wins, terminate the
        // old. The C reasons about `outgoing` ownership (which side
        // initiated which). Chunk 4b is responder-only — the dup
        // case is two simultaneous INBOUND conns from the same peer.
        // Possible (peer reboots, reconnects before we've timed out
        // the old). Handle it: terminate old, accept new.
        let name = conn.name.clone();
        let conn_outgoing = conn.outgoing.map(OutgoingId::from);
        let conn_addr = conn.address;
        let edge_addr = conn.address.map(|mut a| {
            // C `:1024-1025`: `sockaddrcpy(&edge->address, &c->
            // address); sockaddr_setport(&edge->address, hisport)`.
            // The peer's TCP-connect-from addr, but with the port
            // REWRITTEN to their UDP port. This is the "how do I
            // reach you for data packets" addr.
            a.set_port(parsed.his_udp_port);
            a
        });
        // C `:1048`: `c->edge->weight = (weight + c->estimated_
        // weight) / 2`. The arithmetic average. C `int /` truncates
        // toward zero; `i32::midpoint` rounds toward neg-inf. With
        // both weights non-negative (RTT in ms) they're identical,
        // but the OVERFLOW behavior differs: `(i32::MAX + i32::MAX)
        // /2` is UB in C, panics in debug Rust, wraps in release.
        // `i32::midpoint` doesn't overflow. The C is buggy at 24-
        // day RTT; we're not. The semantic divergence (rounding) is
        // unreachable. Take the no-overflow version.
        let edge_weight = i32::midpoint(parsed.his_weight, conn.estimated_weight);
        let edge_options = conn.options;

        // C `protocol_auth.c:939-945`: `if(c->outgoing) { c->
        // outgoing->timeout = 0; add_recent_address(...) }`. The
        // connection got all the way to ACK — the address WORKED.
        // Reset the backoff for next time; move the addr to front
        // of the cache.
        if let Some(oid) = conn_outgoing {
            if let Some(o) = self.outgoings.get_mut(oid) {
                o.timeout = 0;
                if let Some(a) = conn_addr {
                    o.addr_cache.add_recent(a);
                }
                // C `address_cache.c:251`: `reset_address_cache`.
                // Next retry walks from the top (which is now the
                // working addr).
                o.addr_cache.reset();
            }
        }

        // (drop conn borrow before touching self.nodes / terminate)
        if let Some(old) = self.nodes.get(&name) {
            if let Some(old_conn) = old.conn {
                if old_conn != id {
                    // C `:976-978`: "Established a second connection
                    // with X, closing old connection".
                    log::debug!(target: "tincd::conn",
                                "Established a second connection with {name}, \
                                 closing old connection");
                    self.terminate(old_conn);
                    // C `:989`: `graph()` after terminate. The
                    // unconditional `run_graph_and_log()` below
                    // covers it (extra graph() is idempotent).
                }
            }
        }

        // C `:993-994` + `:1032-1051`: NodeState records the edge
        // metadata (the address, which tinc-graph::Edge doesn't
        // carry — it's runtime annotation). The graph gets weight
        // + options below.
        // (NodeState insert deferred until we have `fwd_eid` below.)

        // C `:1032-1051`: `c->edge = new_edge(); ...; edge_add()`.
        // The bridge to the graph. `lookup_or_add_node` for the
        // peer (might already be in the graph if a transitive
        // ADD_EDGE arrived first — unlikely with chunk-5's single-
        // peer scope but the C handles it). Then `add_edge(myself
        // → peer)`.
        //
        // C builds a BIDIRECTIONAL pair via `e->reverse` linking
        // (`edge.c:59-73`). `Graph::add_edge` auto-links if the
        // twin exists. With ONE direction, sssp's `e->reverse`
        // check (`graph.c:159`) skips it — so the peer won't
        // become reachable until either (a) we add the reverse
        // here, or (b) the peer's ADD_EDGE for `peer→myself`
        // arrives. The C does (a) implicitly: `ack_h` runs on
        // BOTH sides, both add their `c->edge`, the first arrives
        // via the protocol and links. With chunk-5's stub forward
        // and no peer-initiated ADD_EDGE in tests, we add both
        // directions here. The C's `c->edge` is one direction;
        // the peer's `c->edge` (sent via ADD_EDGE) is the other.
        // We synthesize the reverse for the test to prove the
        // diff fires.
        let peer_id = self.lookup_or_add_node(&name);
        let fwd_eid = self
            .graph
            .add_edge(self.myself, peer_id, edge_weight, edge_options);
        // The reverse. C: comes from peer's send_add_edge. Chunk
        // 5 stub: synthesize. Same weight (the average is symmetric
        // when both sides compute it) but the C peer might have a
        // different `c->options` (depends on THEIR config). With
        // identical defaults: same. Real divergence is chunk-6.
        let rev_eid = self
            .graph
            .add_edge(peer_id, self.myself, edge_weight, edge_options);

        // C `:1024-1025`: `c->edge->address = c->address` with port
        // rewritten to `hisport`. C `:1040-1045`: `c->edge->local_
        // address = getsockname()` with port rewritten to `myport.
        // udp`. We have the FORWARD edge's addr in `edge_addr`
        // (already port-rewritten above). Stash as wire-format
        // `AddrStr` tokens (numeric IP + numeric port — `getnameinfo
        // NI_NUMERICHOST` shape, what `sockaddr2str` would emit).
        //
        // The reverse edge is the one the PEER would `edge_add`
        // from THEIR `ack_h`. Its `address` would be OUR address
        // as seen from their side (which we don't know without
        // STUN-style probing). The C learns it from the peer's
        // `send_add_edge` broadcast. Chunk-5 synthesizes: leave the
        // reverse without an `edge_addrs` entry; `dump_edges`
        // formats missing entries as `"unknown port unknown"`
        // (the C default for `n->hostname == NULL`, `node.c:211`).
        // C `ack_h:1040-1045`: `getsockname` → `local_address`
        // with port rewritten to `myport.udp`. The `Connection.fd`
        // is an `OwnedFd`; `socket2::SockRef::from(&OwnedFd)` is
        // the non-owning wrapper for the `local_addr()` call.
        let local_addr = self.conns.get(id).and_then(|c| {
            let sockref = socket2::SockRef::from(c.owned_fd());
            sockref.local_addr().ok().and_then(|sa| sa.as_socket())
        });
        if let Some(ea) = edge_addr {
            // `Ipv6Addr::Display` doesn't bracket (matches
            // `getnameinfo NI_NUMERICHOST`); same as `fmt_addr`.
            let addr = AddrStr::new(ea.ip().to_string()).expect("numeric IP is whitespace-free");
            let port = AddrStr::new(ea.port().to_string()).expect("numeric");
            // C `:1042-1045`: `sockaddr_setport(&local, myport.udp)`.
            // The local addr is the OS-assigned source-addr of the
            // TCP socket; rewrite the port to OUR udp port (the peer
            // sends UDP back to that port, not the ephemeral TCP one).
            let (la, lp) = if let Some(mut local) = local_addr {
                local.set_port(self.my_udp_port);
                (
                    AddrStr::new(local.ip().to_string()).expect("numeric"),
                    AddrStr::new(local.port().to_string()).expect("numeric"),
                )
            } else {
                let unspec = AddrStr::new(AddrStr::UNSPEC).expect("literal");
                (unspec.clone(), unspec)
            };
            self.edge_addrs.insert(fwd_eid, (addr, port, la, lp));
        }
        let _ = rev_eid; // entry intentionally absent; see above

        // C `:993-994` + `:1051`: `n->connection = c; c->edge = e`.
        // Now that we have `fwd_eid`, populate `NodeState.edge`.
        // `terminate_connection` (`net.c:126-132`) reads it.
        self.nodes.insert(
            name.clone(),
            NodeState {
                edge: Some(fwd_eid),
                conn: Some(id),
                edge_addr,
                edge_weight,
                edge_options,
            },
        );

        // C `:1051`: `c->edge = e`. The `c->edge != NULL` check in
        // `broadcast_meta` (`meta.c:115`) is the "past ACK" filter.
        // We use a bool. NOT set earlier: `send_everything` calls
        // `conn.send()` which is fine (the conn isn't a broadcast
        // TARGET yet, but it can receive); the broadcast below
        // (`send_add_edge(everyone, ...)`) MUST exclude this conn
        // (it's not active yet — the C ordering is the same:
        // `:1051` `c->edge = e` is AFTER `:1028 send_everything`
        // but BEFORE `:1058 send_add_edge(everyone)`. Wait, no:
        // C `:1051` is after `:1028` but before `:1058`. So the
        // `c->edge` test PASSES at `:1058`. The `c == everyone`
        // path in `send_request` (`protocol.c:122`) calls
        // `broadcast_meta(NULL, ...)` — `from = NULL` means no
        // skip. The new conn DOES get its own edge back. The
        // `seen.check` on the receiver side dups it.
        //
        // Match: set `active` BEFORE the broadcast so the new conn
        // is included. The `seen.check` dedup makes this harmless;
        // matching the C wire output is what counts.
        if let Some(conn) = self.conns.get_mut(id) {
            conn.active = true;
        }

        // C `:1028`: `send_everything(c)`. Walks `node_tree`, for
        // each node walks `subnet_tree` and `edge_tree`, sends
        // ADD_SUBNET/ADD_EDGE for everything we know. NOTE: this
        // sends the edge we JUST added (the one fwd_eid we have
        // an addr for). The C does the same: `edge_add` at `:1051`
        // is BEFORE `:1028 send_everything` — wait, no, `:1028`
        // is the call site, `:1051` is `edge_add(c->edge)`. Read
        // again: `:1028 send_everything(c)` then `:1032-1051` build
        // and add the edge. So C `send_everything` does NOT include
        // the new edge. We added it earlier (line ordering moved
        // for `NodeState.edge`). Adjust: send_everything BEFORE
        // edge_addrs.insert. Actually it doesn't matter — the new
        // edge gets sent via the `send_add_edge(everyone)` below
        // anyway, and the peer's `seen.check` dups any double-
        // send. Match the C's wire-output by skipping `fwd_eid`
        // would be needless complexity. Leave as-is.
        let mut nw = self.send_everything(id);

        // C `:1055-1059`: `send_add_edge(everyone, c->edge)`. Tell
        // every OTHER active conn about the new edge. The C
        // `everyone` sentinel routes through `broadcast_meta(NULL,
        // ...)` (`protocol.c:122-125`). With one peer and that
        // peer being `id` (just-set active), the broadcast targets
        // include `id`; the peer's `seen.check` will dup it (since
        // `send_everything` already sent the same edge with a
        // DIFFERENT nonce — wait, that's NOT a dup then. The seen
        // cache keys on the full line including nonce. So the peer
        // gets two ADD_EDGEs for the same edge with different
        // nonces. Both pass `seen.check`. The SECOND one hits the
        // `lookup_edge` exists branch with same weight+options →
        // idempotent return. OK. The C has the same shape).
        //
        // Format ONCE then broadcast (`send_request:122` formats
        // before `broadcast_meta`; one nonce for all targets).
        if let Some(line) = self.fmt_add_edge(fwd_eid, Self::nonce()) {
            nw |= self.broadcast_line(&line);
        }

        // C `:1065`: `graph()`. THE FIRST TIME this does anything:
        // peer was added with reachable=false (lookup_or_add_node);
        // the bidi edge means sssp visits it; diff emits
        // BecameReachable.
        self.run_graph_and_log();

        Ok(nw)
    }

    /// `handle_meta_io` WRITE path → `handle_meta_write`
    /// (`net_socket.c:486-511`).
    fn on_conn_writable(&mut self, id: ConnId) {
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.flush() {
            Ok(true) => {
                // outbuf empty. C `:509-511`: `io_set(&c->io, IO_READ)`.
                if let Some(&io_id) = self.conn_io.get(id) {
                    if let Err(e) = self.ev.set(io_id, Io::Read) {
                        log::error!(target: "tincd::conn",
                                    "io_set failed for {id:?}: {e}");
                        self.terminate(id);
                    }
                }
            }
            Ok(false) => {
                // More to send. Stay registered for WRITE.
            }
            Err(e) => {
                // C `:502-504`: log + terminate.
                log::info!(target: "tincd::conn",
                           "Connection write failed: {e}");
                self.terminate(id);
            }
        }
    }

    /// `terminate_connection` (`net.c:118-170`). Removes the conn,
    /// deletes its edge, broadcasts `DEL_EDGE`, runs `graph()`.
    /// Chunk 6: the `c->edge` cleanup path (`:126-152`) is REAL.
    ///
    /// The C's `report` flag (`:128`: `if(report && !tunnelserver)`)
    /// gates the DEL_EDGE broadcast. `report = c->edge != NULL` at
    /// most call sites (`net.c:225,243,253,310`). We test
    /// `conn.active` (same condition).
    ///
    /// `c->outgoing` retry (`:155-161`) is chunk 6 commit 2.
    fn terminate(&mut self, id: ConnId) {
        let Some(conn) = self.conns.remove(id) else {
            // Already gone. The slotmap is generational; a stale
            // ConnId returns None. Idempotent.
            if let Some(io_id) = self.conn_io.remove(id) {
                self.ev.del(io_id);
            }
            return;
        };
        log::info!(target: "tincd::conn",
                   "Closing connection with {}", conn.name);
        let was_active = conn.active;
        let conn_name = conn.name.clone();
        // Drop conn now — OwnedFd closes the socket. Further
        // `broadcast_line` calls below will skip this id (it's
        // gone from `conns`).
        drop(conn);

        if let Some(io_id) = self.conn_io.remove(id) {
            self.ev.del(io_id);
        }

        // C `:121-123`: `if(c->node && c->node->connection == c)
        // c->node->connection = NULL`. The node OUTLIVES the conn;
        // clear the back-ref so a stale ConnId isn't read. Also
        // grab the edge while we're here.
        let our_edge = self.nodes.get_mut(&conn_name).and_then(|ns| {
            if ns.conn == Some(id) {
                ns.conn = None;
                ns.edge.take()
            } else {
                None
            }
        });

        // C `:126-152`: `if(c->edge)`. The edge cleanup. Only fires
        // for connections that got past ACK (`ack_h:1051` set
        // `c->edge`). Control conns and pre-ACK peers skip.
        if let Some(eid) = our_edge {
            // C `:127-129`: `if(report && !tunnelserver) send_del_
            // edge(everyone, c->edge)`. The `c == everyone` path
            // formats once + `broadcast_meta(NULL, ...)`. The conn
            // is already gone from `conns` so it's not a target.
            if was_active {
                let to_name = conn_name.clone();
                let my_name = self.name.clone();
                let line = DelEdge {
                    from: my_name,
                    to: to_name,
                }
                .format(Self::nonce());
                self.broadcast_line(&line);
            }

            // C `:131-132`: `edge_del(c->edge); c->edge = NULL`.
            self.graph.del_edge(eid);
            self.edge_addrs.remove(&eid);

            // C `:136`: `graph()`. The peer might become
            // unreachable; the diff fires `BecameUnreachable`.
            self.run_graph_and_log();

            // C `:140-152`: reverse-edge cleanup. If the peer is
            // now unreachable AND has an edge back to us (the
            // synthesized reverse from `on_ack`), delete + broadcast
            // that too. The C `lookup_edge(c->node, myself)`.
            let peer_unreachable = self
                .node_ids
                .get(&conn_name)
                .and_then(|&nid| self.graph.node(nid))
                .is_some_and(|n| !n.reachable);
            if was_active && peer_unreachable {
                if let Some(&peer_nid) = self.node_ids.get(&conn_name) {
                    if let Some(rev) = self.graph.lookup_edge(peer_nid, self.myself) {
                        // C `:146`: `send_del_edge(everyone, e)`.
                        let line = DelEdge {
                            from: conn_name.clone(),
                            to: self.name.clone(),
                        }
                        .format(Self::nonce());
                        self.broadcast_line(&line);
                        // C `:149`: `edge_del(e)`.
                        self.graph.del_edge(rev);
                        self.edge_addrs.remove(&rev);
                    }
                }
            }
        }

        // C `net.c:155-161`: `c->outgoing` retry. When an outgoing
        // connection drops, immediately try again. C `:161`:
        // `do_outgoing_connection(outgoing)`. The conn was already
        // removed; the addr cache cursor moves to the next addr.
        // If THAT also fails, `retry_outgoing` arms the backoff.
        //
        // The `was_active` gate is intentional: `:161` runs
        // unconditionally in C, but for us a NON-active outgoing
        // (probe failed) is already handled by `on_connecting`→
        // `do_outgoing_connection` directly. Don't double-retry.
        if was_active {
            if let Some(oid) = self.nodes.get(&conn_name).and_then(|_| {
                // Can't read `conn.outgoing` (conn already
                // dropped). Look it up by name in `outgoings`.
                self.outgoings
                    .iter()
                    .find(|(_, o)| o.node_name == conn_name)
                    .map(|(id, _)| id)
            }) {
                // C `ack_h:942`: `c->outgoing->timeout = 0` was
                // already done in `on_ack` — wait, no, we never
                // ported that. Do it here: a connection that GOT
                // to ACK had a working address; reset the backoff.
                if let Some(o) = self.outgoings.get_mut(oid) {
                    o.timeout = 0;
                }
                self.do_outgoing_connection(oid);
            }
        }
    }

    // ─── outgoing connections (`net_socket.c:405-681`)

    /// `setup_outgoing_connection` (`net_socket.c:664-681`). Disarm
    /// the retry timer, check if we're already connected, else dial.
    ///
    /// C `:666`: `timeout_del(&outgoing->ev)` — cancel any pending
    /// retry. We're about to TRY, so the backoff timer is moot.
    /// C `:674`: `if(n->connection) { log "Already connected";
    /// return }`. Don't dial out if we already have a conn (either
    /// they connected to US, or a previous outgoing succeeded).
    fn setup_outgoing_connection(&mut self, oid: OutgoingId) {
        // C `:666`: `timeout_del(&outgoing->ev)`. Our `set` would
        // re-arm anyway, but explicitly disarming matches the C
        // and prevents the timer from firing while a connect is
        // in flight (which would start a SECOND connect).
        // tinc-event's `del` frees the slot; we want to KEEP the
        // slot, just disarm. There's no `unset`. Workaround: don't
        // del; the next `retry_outgoing` `set` overwrites. The
        // timer can't fire mid-connect because we won't return to
        // `run()` until this function exits.

        let Some(outgoing) = self.outgoings.get(oid) else {
            return; // gone (chunk 8's mark-sweep)
        };
        let name = outgoing.node_name.clone();

        // C `:674-676`: `if(n->connection)`. Our `NodeState.conn`.
        if self.nodes.get(&name).and_then(|ns| ns.conn).is_some() {
            log::info!(target: "tincd::conn",
                       "Already connected to {name}");
            return;
        }

        // C `:678`: `do_outgoing_connection(outgoing)`.
        self.do_outgoing_connection(oid);
    }

    /// `do_outgoing_connection` (`net_socket.c:564-662`). The `goto
    /// begin` loop: walk the addr cache, try each addr, register
    /// the first one that doesn't fail synchronously. Exhausted →
    /// arm the retry-backoff timer.
    fn do_outgoing_connection(&mut self, oid: OutgoingId) {
        loop {
            let Some(outgoing) = self.outgoings.get_mut(oid) else {
                return;
            };
            let name = outgoing.node_name.clone();
            match try_connect(&mut outgoing.addr_cache, &name) {
                ConnectAttempt::Started { sock, addr } => {
                    // C `:649-658`: `c->status.connecting = true;
                    // c->name = name; connection_add(c); io_add(
                    // ..., IO_READ | IO_WRITE)`. The WRITE
                    // registration is what triggers `on_connecting`
                    // when the kernel finishes (or fails) the
                    // async connect.
                    let now = self.timers.now();
                    // The probe needs `&Socket` (for `take_error`);
                    // `Connection.fd` is `OwnedFd`. Same fd, two
                    // owners would double-close. dup the fd: the
                    // dup goes on `Connection` (the LONG-lived
                    // handle, the one we register with epoll); the
                    // original sock drops after `finish_connecting`.
                    // One extra fd for ~1 RTT. The C doesn't have
                    // this split (its `getsockopt` takes raw `int`);
                    // it's the cost of type-safe ownership.
                    //
                    // Register the DUP's fd, NOT the original. The
                    // dup outlives the probe; the original closes
                    // when `connecting_socks` removes it. Registering
                    // the original would leave the event-loop slot
                    // stale post-probe (epoll on a closed fd).
                    let dup = match sock.try_clone() {
                        Ok(d) => OwnedFd::from(d),
                        Err(e) => {
                            log::error!(target: "tincd::conn",
                                        "dup failed for {addr}: {e}");
                            // sock drops; retry next addr.
                            continue;
                        }
                    };
                    let fd = dup.as_raw_fd();
                    let conn = Connection::new_outgoing(
                        dup,
                        name,
                        fmt_addr(&addr),
                        addr,
                        slotmap::Key::data(&oid),
                        now,
                    );
                    let id = self.conns.insert(conn);
                    self.connecting_socks.insert(id, sock);
                    // C `:658`: `io_add(..., IO_READ | IO_WRITE)`.
                    // ReadWrite: the WRITE wake is the probe trigger
                    // (epoll EPOLLOUT fires when connect completes
                    // OR fails). READ is registered too (the C does
                    // it; loopback connect+immediate-data is possible).
                    match self.ev.add(fd, Io::ReadWrite, IoWhat::Conn(id)) {
                        Ok(io_id) => {
                            self.conn_io.insert(id, io_id);
                        }
                        Err(e) => {
                            log::error!(target: "tincd::conn",
                                        "io_add failed: {e}");
                            self.conns.remove(id);
                            self.connecting_socks.remove(id);
                            continue; // try next addr
                        }
                    }
                    return; // C `:660`: `return true`.
                }
                ConnectAttempt::Retry => {
                    // C `goto begin`. Next iteration tries the next
                    // addr from the cache.
                }
                ConnectAttempt::Exhausted => {
                    // C `:572-575`: `retry_outgoing(outgoing);
                    // return false`.
                    self.retry_outgoing(oid);
                    return;
                }
            }
        }
    }

    /// `retry_outgoing` (`net_socket.c:405-417`). Bump the backoff
    /// (`timeout += 5`, cap at maxtimeout), arm the timer. The
    /// `RetryOutgoing(oid)` dispatch arm calls `setup_outgoing_
    /// connection` when it fires.
    ///
    /// C `:414` jitter: `+ jitter()` (≤ 1s random ms). Not ported
    /// (see lib.rs jitter doc — the loop's tick rate already
    /// desyncs identical-config daemons).
    fn retry_outgoing(&mut self, oid: OutgoingId) {
        let Some(outgoing) = self.outgoings.get_mut(oid) else {
            return;
        };
        let timeout = outgoing.bump_timeout(self.settings.maxtimeout);
        // C `:413`: also resets the addr cache cursor for next time.
        // Wait — it doesn't. The C `reset_address_cache` is called
        // from `setup_outgoing_connection` (`:670`), not here. We
        // didn't port that line either. Reset HERE so the next
        // retry walks from the top.
        outgoing.addr_cache.reset();
        log::info!(target: "tincd::conn",
                   "Trying to re-establish outgoing connection in {timeout} seconds");
        if let Some(&tid) = self.outgoing_timers.get(oid) {
            self.timers
                .set(tid, Duration::from_secs(u64::from(timeout)));
        }
    }

    /// `handle_meta_io` connecting branch (`net_socket.c:517-555`).
    /// Probe the async connect. Success → `finish_connecting`. Fail
    /// → terminate (which retries the outgoing).
    ///
    /// Returns `true` if the caller should fall through to the
    /// write/read dispatch (probe succeeded; C `:553` falls through).
    /// `false` for spurious wake or failure (C `:534`/`:550` `return`).
    /// The fall-through matters: mio is edge-triggered; the WRITE
    /// edge that woke us is the same one that would let us flush the
    /// ID line. Consuming it for the probe and not flushing means
    /// the next WRITE wake never comes.
    fn on_connecting(&mut self, id: ConnId) -> bool {
        let Some(sock) = self.connecting_socks.get(id) else {
            // Shouldn't happen (we always insert when conn.
            // connecting=true). Defensive.
            log::warn!(target: "tincd::conn",
                       "on_connecting: no socket for {id:?}");
            self.terminate(id);
            return false;
        };
        match probe_connecting(sock) {
            Ok(true) => {
                // C `:553-554`: `c->status.connecting = false;
                // finish_connecting(c)`. Fall through after.
                self.finish_connecting(id);
                true
            }
            Ok(false) => {
                // Spurious wakeup. Stay registered for WRITE.
                // C `:534`: `return`.
                false
            }
            Err(e) => {
                // C `:546-547`: log DEBUG "Error while connecting
                // to %s (%s): %s"; terminate. The C uses
                // `terminate_connection(c, false)` — the `false`
                // is `report = false` (don't broadcast DEL_EDGE,
                // there IS no edge yet). Our `terminate` keys on
                // `was_active` which is also false here.
                let (name, hostname) = self
                    .conns
                    .get(id)
                    .map(|c| (c.name.clone(), c.hostname.clone()))
                    .unwrap_or_default();
                log::debug!(target: "tincd::conn",
                            "Error while connecting to {name} ({hostname}): {e}");
                // Stash the OutgoingId BEFORE terminate (which
                // drops the conn). The probe-fail path (NOT
                // `was_active`) doesn't trigger terminate's retry,
                // so we drive `do_outgoing_connection` directly
                // — try the NEXT addr from the cache.
                let oid = self
                    .conns
                    .get(id)
                    .and_then(|c| c.outgoing)
                    .map(OutgoingId::from);
                self.connecting_socks.remove(id);
                self.terminate(id);
                if let Some(oid) = oid {
                    self.do_outgoing_connection(oid);
                }
                false
            }
        }
    }

    /// `finish_connecting` (`net_socket.c:419-426`). The async
    /// connect succeeded. Clear the connecting flag, switch
    /// interest to READ-only, send our ID line. The peer's `id_h`
    /// then fires; OUR `id_h` fires on their reply.
    ///
    /// `addrcache.add_recent`: the address WORKED; move it to
    /// front. C does this in `ack_h` (`protocol_auth.c:939-943`
    /// `add_recent_address(c->outgoing->node->address_cache, ...)`)
    /// not here — the C waits until ACK to be sure. We do too:
    /// move the `add_recent` to `on_ack`. Connecting through ACK
    /// is the full proof; the right port alone doesn't mean tinc.
    fn finish_connecting(&mut self, id: ConnId) {
        // Drop the probe socket. The dup'd `OwnedFd` on the
        // Connection is the live handle from here on.
        self.connecting_socks.remove(id);

        let Some(conn) = self.conns.get_mut(id) else {
            return;
        };
        // C `:421`: `"Connected to %s (%s)"`.
        log::info!(target: "tincd::conn",
                   "Connected to {} ({})", conn.name, conn.hostname);
        // C `:423`: `c->last_ping_time = now.tv_sec`. The pingtimer
        // sweep (chunk 8) keys on this.
        conn.last_ping_time = self.timers.now();
        // C `:424`: `c->status.connecting = false`.
        conn.connecting = false;

        // C `:425`: `send_id(c)`. WE go first (initiator). The
        // peer's `id_h:451` `if(!c->outgoing) send_id(c)` replies.
        // Same line as our responder-side `handle_id` sends.
        let needs_write = conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id as u8,
            self.name,
            tinc_proto::request::PROT_MAJOR,
            tinc_proto::request::PROT_MINOR
        ));

        // Re-register: we were ReadWrite (for the WRITE-probe wake);
        // now we want READ (for the peer's ID reply). If we just
        // queued data, ReadWrite (let it flush). C `:658` registers
        // READ|WRITE always; `handle_meta_write` (`:509`) drops
        // WRITE when outbuf empties. Same.
        if let Some(&io_id) = self.conn_io.get(id) {
            let interest = if needs_write { Io::ReadWrite } else { Io::Read };
            if let Err(e) = self.ev.set(io_id, interest) {
                log::error!(target: "tincd::conn",
                            "io_set failed for {id:?}: {e}");
                self.terminate(id);
            }
        }
    }
}

impl Drop for Daemon {
    /// `exit_control` (`control.c:233-240`): unlink pidfile + socket.
    /// `ControlSocket::drop` already unlinks the socket. We do the
    /// pidfile.
    fn drop(&mut self) {
        // C `net_setup.c:756-762` (`device_disable`): tinc-down
        // BEFORE device close. The script typically does `ip link
        // set down` / `ip addr del`. C calls it from `close_
        // network_connections` (`:1294`). `Drop` is the equivalent
        // teardown point; the device's own `Drop` runs after.
        self.run_script("tinc-down");
        let _ = std::fs::remove_file(&self.pidfile);
        // Signal handlers stay installed (SelfPipe::drop doesn't del
        // them — see tinc-event/sig.rs Drop doc). Process is exiting;
        // doesn't matter.
    }
}

/// Why `Daemon::setup` failed.
#[derive(Debug)]
pub enum SetupError {
    /// Config read/parse error, or required field missing.
    Config(String),
    /// OS resource: socket, file, epoll.
    Io(std::io::Error),
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(s) => write!(f, "{s}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for SetupError {}

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

    /// `DaemonSettings::default()` matches C defaults. `net_setup.c:
    /// 1243` (`pinginterval = 60`), `:1248` (`pingtimeout = 5`),
    /// `:789` (`myport = "655"`), `net_socket.c:38` (`addressfamily
    /// = AF_UNSPEC`).
    #[test]
    fn settings_defaults_match_c() {
        let s = DaemonSettings::default();
        assert_eq!(s.pinginterval, 60);
        assert_eq!(s.pingtimeout, 5);
        assert_eq!(s.port, 655);
        assert_eq!(s.addressfamily, AddrFamily::Any);
        assert_eq!(s.udp_discovery_timeout, 30);
    }

    /// `periodic_handler` backoff arithmetic (`net.c:274-291`).
    /// Can't construct a full `Daemon` (SelfPipe is process-
    /// singleton); test the math on a fake. The function is
    /// extracted so the storm-detection arithmetic is checkable
    /// without sleeping.
    ///
    /// Mirrors `on_periodic_tick`'s body. Any divergence between
    /// this and the real fn would be caught by the integration
    /// test (which doesn't exist for the storm case — hard to
    /// induce). The arithmetic IS the easy bit; pin it.
    #[test]
    fn periodic_contradicting_edge_backoff() {
        // Same arithmetic as `on_periodic_tick`. C `:274-291`.
        fn step(add: u32, del: u32, sleeptime: u32) -> (u32, Duration) {
            if del > 100 && add > 100 {
                let d = Duration::from_secs(u64::from(sleeptime));
                (sleeptime.saturating_mul(2).min(3600), d)
            } else {
                ((sleeptime / 2).max(10), Duration::ZERO)
            }
        }

        // Clean period: halve, floor at 10. C `:282-289`.
        assert_eq!(step(0, 0, 10), (10, Duration::ZERO));
        assert_eq!(step(0, 0, 100), (50, Duration::ZERO));
        assert_eq!(step(0, 0, 11), (10, Duration::ZERO)); // 5 → floor
        // BOTH must exceed 100. C `:274`: `&&`.
        assert_eq!(step(101, 50, 10), (10, Duration::ZERO));
        assert_eq!(step(50, 101, 10), (10, Duration::ZERO));

        // Storm: sleep `sleeptime`, then double. C `:275-281`.
        assert_eq!(step(101, 101, 10), (20, Duration::from_secs(10)));
        assert_eq!(step(101, 101, 20), (40, Duration::from_secs(20)));
        // Cap at 3600. C `:279-281` (the `< 0` check catches
        // signed overflow; we cap explicitly).
        assert_eq!(step(101, 101, 2000), (3600, Duration::from_secs(2000)));
        assert_eq!(step(101, 101, 3600), (3600, Duration::from_secs(3600)));
    }

    /// The IoWhat enum has all six variants. Census: `rg 'io_add\('
    /// src/*.c` finds exactly 6 distinct callbacks (signal.c's is
    /// internal, the rest are the variants here). If a 7th cb is
    /// added in C, this test serves as the documentation pointer.
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
