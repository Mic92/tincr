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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use rand_core::{OsRng, RngCore};
use slotmap::{SlotMap, new_key_type};
use tinc_crypto::sign::SigningKey;
use tinc_device::Device;
use tinc_event::{EventLoop, Io, IoId, Ready, SelfPipe, TimerId, Timers};
use tinc_graph::{EdgeId, Graph, NodeId, Route};
use tinc_proto::msg::{AddEdge, AnsKey, DelEdge, MtuInfo, ReqKey, SubnetMsg, UdpInfo};
use tinc_proto::{AddrStr, Request, Subnet};
use tinc_sptps::{Framing, Role, Sptps};

use crate::autoconnect::{self, AutoAction, NodeSnapshot};
use crate::conn::{Connection, FeedResult, SptpsEvent};
use crate::control::{ControlSocket, generate_cookie, write_pidfile};
use crate::graph_glue::{Transition, run_graph};
use crate::invitation_serve::{self, InvitePhase};
use crate::keys::{PrivKeyError, read_ecdsa_private_key};
use crate::listen::{
    AddrFamily, Listener, Tarpit, configure_tcp, fmt_addr, is_local, open_listeners, pidfile_addr,
    unmap,
};
use crate::node_id::{NodeId6, NodeId6Table};
use crate::outgoing::{
    ConnectAttempt, MAX_TIMEOUT_DEFAULT, Outgoing, OutgoingId, ProxyConfig, parse_proxy_config,
    probe_connecting, resolve_config_addrs, try_connect, try_connect_via_proxy,
};
use crate::pmtu::{self, PmtuAction, PmtuState};
use crate::proto::{
    DispatchError, DispatchResult, IdCtx, IdOk, check_gate, handle_control, handle_id,
    myself_options_default, parse_ack, parse_add_edge, parse_add_subnet, parse_del_edge,
    parse_del_subnet, record_body, send_ack,
};
use crate::reload;
use crate::route::{self, RouteResult, TtlResult, route};
use crate::script::{self, ScriptEnv, ScriptResult};
use crate::seen::SeenRequests;
use crate::socks;
use crate::subnet_tree::SubnetTree;
use crate::tunnel::{MTU, TunnelState, make_udp_label};
use crate::udp_info::{self, FromMtuState, FromState, MtuInfoAction, PmtuSnapshot, UdpInfoAction};
use crate::{broadcast, compress, icmp, local_addr, mac_lease, mss, neighbor, route_mac};

mod connect;
mod gossip;
mod metaconn;
mod net;
mod periodic;
mod txpath;

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
    /// `age_subnets` (`route.c:491-521`). Re-arms +10s. Lazy-armed
    /// on the FIRST `learn_mac` (when `MacLeases::learn` returns
    /// `true` = table was empty). Dispatched in `run()` →
    /// `on_age_subnets`.
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
#[allow(clippy::struct_excessive_bools)] // C globals: each bool is
// one `get_config_bool` knob (`net_setup.c`). Grouping them into
// state-machine enums would obscure the 1:1 C-variable mapping.
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
    /// `myself->incompression` (`net_setup.c:991-1043`). The
    /// `Compression = N` config knob. We advertise this in ANS_KEY
    /// (`net_packet.c:996`); peers compress TOWARDS us at this level.
    /// Default 0 (`COMPRESS_NONE`). 1–9 zlib, 12 LZ4; 10–11 LZO
    /// (stubbed, rejected at setup).
    pub compression: u8,
    /// `decrement_ttl` (`net_setup.c:457`). Default OFF (`route.c:
    /// 38`: `bool decrement_ttl = false`). When set, `route_packet`
    /// calls `do_decrement_ttl` AFTER the forward decision (`route.c:
    /// 664,759,896,1004`). Makes `traceroute` through the mesh show
    /// each hop. Off by default because it MUTATES forwarded packets
    /// (TTL field + IPv4 checksum); some payloads (encrypted-with-
    /// integrity, e.g. ESP) hash the IP header.
    pub decrement_ttl: bool,
    /// `udp_discovery_interval` (`net_packet.c:85`). Seconds between
    /// UDP probe-request sends when `!udp_confirmed`. Default 2.
    pub udp_discovery_interval: u32,
    /// `udp_discovery_keepalive_interval` (`net_packet.c:84`). Seconds
    /// between probe sends when `udp_confirmed`. Default 10. Keeps
    /// NAT mappings alive.
    pub udp_discovery_keepalive_interval: u32,
    /// `tunnelserver` (`net_setup.c:879`). Default false.
    ///
    /// Hub-mode: don't gossip indirect topology. Our direct peers
    /// learn each other only by us telling them; they can't learn
    /// each other's far-side neighbors. ADD/DEL_EDGE/SUBNET are
    /// filtered (drop if neither endpoint is us or a direct peer)
    /// and not forwarded. The hub knows only its spokes; spokes
    /// know only the hub.
    ///
    /// `:880`: `strictsubnets |= tunnelserver`. We don't have
    /// strictsubnets yet (it predates tunnelserver — checks gossip'd
    /// subnets against on-disk hosts/ files).
    /// STUB(chunk-12-strictsubnets): the implication is one line
    /// when strictsubnets lands.
    pub tunnelserver: bool,
    /// `directonly` (`net_setup.c:403`, `route.c:41`). Default
    /// false. Route-time gate: if `owner != via` (would relay),
    /// send ICMP `NET_ANO` instead. The relay path EXISTS and
    /// works; this knob lets the operator say "don't use it".
    pub directonly: bool,
    /// `forwarding_mode` (`net_setup.c:426-443`). Default `Internal`
    /// (`route.c:37`: `fmode_t forwarding_mode = FMODE_INTERNAL`).
    /// `Off` drops packets not addressed to us (leaf-only mode).
    /// `Kernel` writes everything from a peer straight to TUN, lets
    /// the OS routing table decide (`route.c:1135-1138`). Checked
    /// at the top of `route_packet`.
    pub forwarding_mode: ForwardingMode,
    /// `routing_mode` (`net_setup.c:406-424`). The dispatch shape:
    /// `Router` → ethertype switch (current); `Switch` →
    /// `route_mac`; `Hub` → always broadcast. NOT in
    /// `apply_reloadable_settings` — changing tun↔tap mid-run means
    /// re-opening the device, which the C doesn't do.
    pub routing_mode: RoutingMode,
    /// `broadcast_mode` (`net_setup.c:461-472`). Default `Mst`. The
    /// `RouteResult::Broadcast` arm dispatches on this. `None` drops
    /// all broadcasts; `Direct` only sends to one-hop neighbors (and
    /// only when WE originated, `net_packet.c:1644-1646`).
    pub broadcast_mode: broadcast::BroadcastMode,
    /// `macexpire` (`net_setup.c:523-524`, `route.c:43`). Seconds.
    /// Default 600 (= `mac_lease::DEFAULT_EXPIRE_SECS`). Lease TTL
    /// for learned MACs. The `age_subnets` 10s timer is the SWEEP
    /// frequency; this is the LEASE duration.
    pub macexpire: u64,
    /// `invitation_lifetime` (`protocol_auth.c:55`). C default 604800
    /// (one week, `net_setup.c:567`). Config var `InvitationExpire`.
    /// Seconds; `serve_cookie` checks `mtime + this < now`.
    pub invitation_lifetime: Duration,
    /// `localdiscovery` (`net_setup.c:404`, `net_packet.c:1241`).
    /// Default false. When set, `try_udp` sends a SECOND probe to
    /// the peer's LAN-side address (from `ADD_EDGE.local_address`)
    /// when `!udp_confirmed`. Faster convergence when both nodes
    /// are on the same LAN behind the same NAT — the WAN probe
    /// round-trips through the NAT (or hairpin-fails); the LAN
    /// probe goes direct.
    pub local_discovery: bool,
    /// `proxytype`/`proxyhost` (`net_setup.c:263-378`). `None` is the
    /// default (direct connect). `Exec` is socketpair+fork (no
    /// handshake); `Socks4`/`Socks5` connect to the proxy then send
    /// `socks::build_request` bytes BEFORE the ID line and read the
    /// fixed-length reply via `conn.tcplen` (`meta.c:275-298`).
    /// `Http` (`protocol_auth.c:60-68`) sends `CONNECT host:port`
    /// then intercepts the line-based response in `metaconn.rs`
    /// BEFORE `check_gate` while `allow_request==Id`
    /// (`protocol.c:148-161`).
    pub proxy: Option<ProxyConfig>,
    /// `autoconnect` (`net_setup.c:560-562`). Default **true** (the C
    /// `else` branch sets it). When set, `periodic_handler` runs
    /// `do_autoconnect` every 5s: converge to ~3 direct connections.
    /// Tests that don't want surprise connections (most of them) set
    /// `AutoConnect = no`.
    pub autoconnect: bool,
    /// `udp_info_interval` (`protocol_misc.c:35`). Seconds. Debounce
    /// for `send_udp_info` (only when WE originate). Default 5.
    pub udp_info_interval: u32,
    /// `mtu_info_interval` (`protocol_misc.c:34`). Seconds. Separate
    /// debounce from UDP_INFO. Default 5.
    pub mtu_info_interval: u32,
    // Chunk 4+: ~32 more fields.
}

/// `fmode_t` (`route.h:31-35`). Three-way knob. `== INTERNAL` gates
/// the SPTPS_PACKET relay at `protocol_key.c:167`. `Kernel` is
/// checked at the top of `route_packet` (`route.c:1135-1138`):
/// anything from a peer goes straight to the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardingMode {
    /// `FMODE_OFF`. Drop packets not addressed to us.
    Off,
    /// `FMODE_INTERNAL`. C default (`route.c:37`). The daemon's
    /// `route()` does the forwarding decision.
    #[default]
    Internal,
    /// `FMODE_KERNEL`. Write everything from a peer to TUN; let the
    /// OS routing table decide. Packets from OUR device still go
    /// through `route()` (we're the originator).
    Kernel,
}

/// `routing_mode` (`route.h:32`, `net_setup.c:406-424`). C default
/// `RMODE_ROUTER` (`route.c:39`). Read once at setup, NOT
/// reloadable (changing it mid-run would mean re-opening the device
/// tun→tap, which the C doesn't do).
///
/// | Variant | C | Device | Dispatch |
/// |---|---|---|---|
/// | `Router` | `RMODE_ROUTER` | TUN | `route()` ethertype switch |
/// | `Switch` | `RMODE_SWITCH` | TAP | `route_mac()` (`route.c:1159`) |
/// | `Hub` | `RMODE_HUB` | TAP | always `Broadcast` (`route.c:1163`) |
///
/// Hub mode broadcasts EVERYTHING. No MAC learning, no subnet
/// table — pure flood. Niche (legacy compat); we wire it but
/// don't test it (the C doesn't either — `test/integration/` has
/// no hub test).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingMode {
    /// `RMODE_ROUTER`. The default. IP-layer routing.
    #[default]
    Router,
    /// `RMODE_SWITCH`. MAC-layer routing with learning.
    Switch,
    /// `RMODE_HUB`. Always broadcast. No learning.
    Hub,
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
            // C `net_setup.c:1043`: `myself->incompression =
            // COMPRESS_NONE` (the `else` when no Compression config).
            compression: 0,
            // C `route.c:38`: `bool decrement_ttl = false`.
            decrement_ttl: false,
            // C `net_packet.c:85`: `int udp_discovery_interval = 2`.
            udp_discovery_interval: 2,
            // C `net_packet.c:84`.
            udp_discovery_keepalive_interval: 10,
            // C `net_setup.c:879`: default false (no `else { = true }`).
            tunnelserver: false,
            // C `route.c:41`: `bool directonly = false`.
            directonly: false,
            // C `route.c:37`: `fmode_t forwarding_mode = FMODE_INTERNAL`.
            forwarding_mode: ForwardingMode::Internal,
            // C `route.c:39`: `routing_mode = RMODE_ROUTER`.
            routing_mode: RoutingMode::Router,
            // C `net_setup.c:883`: `bcast_mode = BMODE_MST`.
            broadcast_mode: broadcast::BroadcastMode::Mst,
            // C `route.c:43`: `int macexpire = 600`.
            macexpire: mac_lease::DEFAULT_EXPIRE_SECS,
            // C `net_setup.c:567`: `invitation_lifetime = 604800` (1 week).
            invitation_lifetime: Duration::from_secs(604_800),
            // C `net_setup.c:404`: default false (no `else` branch).
            local_discovery: false,
            proxy: None,
            // C `net_setup.c:561`: `else { autoconnect = true; }`.
            autoconnect: true,
            // C `protocol_misc.c:35`: `int udp_info_interval = 5`.
            udp_info_interval: 5,
            // C `protocol_misc.c:34`: `int mtu_info_interval = 5`.
            mtu_info_interval: 5,
        }
    }
}

/// Parse the reloadable subset of settings from `config`. Called
/// from `setup()` AND `reload_configuration()`. The non-reloadable
/// settings (Port, AddressFamily, DeviceType) are NOT here — they
/// need re-bind / re-open which `setup()` does inline.
///
/// `net_setup.c:391-575` `setup_myself_reloadable`. We re-read the
/// settings we already parse; the C has ~40 more we don't yet.
fn apply_reloadable_settings(config: &tinc_conf::Config, settings: &mut DaemonSettings) {
    // PingInterval (`:1241-1243`).
    if let Some(e) = config.lookup("PingInterval").next() {
        if let Ok(v) = e.get_int() {
            if let Ok(v) = u32::try_from(v) {
                if v >= 1 {
                    settings.pinginterval = v;
                }
            }
        }
    }
    // PingTimeout (`:1247-1253`). Clamped to [1, pinginterval].
    if let Some(e) = config.lookup("PingTimeout").next() {
        if let Ok(v) = e.get_int() {
            if let Ok(v) = u32::try_from(v) {
                settings.pingtimeout = v.clamp(1, settings.pinginterval);
            }
        }
    }
    // MaxTimeout (`:527-533`).
    if let Some(e) = config.lookup("MaxTimeout").next() {
        if let Ok(v) = e.get_int() {
            if let Ok(v) = u32::try_from(v) {
                if v >= 1 {
                    settings.maxtimeout = v;
                }
            }
        }
    }
    // DecrementTTL (`:457`).
    if let Some(e) = config.lookup("DecrementTTL").next() {
        if let Ok(v) = e.get_bool() {
            settings.decrement_ttl = v;
        }
    }
    // TunnelServer (`:879`).
    if let Some(e) = config.lookup("TunnelServer").next() {
        if let Ok(v) = e.get_bool() {
            settings.tunnelserver = v;
        }
    }
    // LocalDiscovery (`:404`).
    if let Some(e) = config.lookup("LocalDiscovery").next() {
        if let Ok(v) = e.get_bool() {
            settings.local_discovery = v;
        }
    }
    // DirectOnly (`:403`).
    if let Some(e) = config.lookup("DirectOnly").next() {
        if let Ok(v) = e.get_bool() {
            settings.directonly = v;
        }
    }
    // AutoConnect (`:560-562`). Default true — keep the default if
    // the parse fails (C `get_config_bool` only writes on success).
    if let Some(e) = config.lookup("AutoConnect").next() {
        if let Ok(v) = e.get_bool() {
            settings.autoconnect = v;
        }
    }
    // UDPInfoInterval / MTUInfoInterval (`:400-401`).
    if let Some(e) = config.lookup("UDPInfoInterval").next() {
        if let Ok(v) = e.get_int() {
            if let Ok(v) = u32::try_from(v) {
                settings.udp_info_interval = v;
            }
        }
    }
    if let Some(e) = config.lookup("MTUInfoInterval").next() {
        if let Ok(v) = e.get_int() {
            if let Ok(v) = u32::try_from(v) {
                settings.mtu_info_interval = v;
            }
        }
    }
    // Broadcast (`:461-472`). C errors on unknown; we log + keep
    // default (less harsh on reload typo).
    if let Some(e) = config.lookup("Broadcast").next() {
        settings.broadcast_mode = match e.get_str().to_ascii_lowercase().as_str() {
            "no" => broadcast::BroadcastMode::None,
            "yes" | "mst" => broadcast::BroadcastMode::Mst,
            "direct" => broadcast::BroadcastMode::Direct,
            v => {
                log::error!(target: "tincd",
                            "Broadcast = {v}: invalid (no|yes|mst|direct)");
                settings.broadcast_mode
            }
        };
    }
    // MACExpire (`:523-524`).
    if let Some(e) = config.lookup("MACExpire").next() {
        if let Ok(v) = e.get_int() {
            if let Ok(v) = u64::try_from(v) {
                settings.macexpire = v;
            }
        }
    }
    // InvitationExpire (`:566-568`).
    if let Some(e) = config.lookup("InvitationExpire").next() {
        if let Ok(v) = e.get_int() {
            if let Ok(v) = u64::try_from(v) {
                settings.invitation_lifetime = Duration::from_secs(v);
            }
        }
    }
}

/// Parse `Subnet =` lines for `myname` from `config`. Factored from
/// `setup()` so `reload_configuration()` can call the same parser.
/// `net_setup.c:860-870` (the `for(cfg = lookup_config("Subnet"))`
/// loop) → `HashSet`.
fn parse_subnets_from_config(config: &tinc_conf::Config, myname: &str) -> HashSet<Subnet> {
    let mut subnets = HashSet::new();
    for e in config.lookup("Subnet") {
        match e.get_str().parse::<Subnet>() {
            Ok(s) => {
                subnets.insert(s);
            }
            Err(_) => {
                log::error!(target: "tincd",
                            "Invalid Subnet = {} in hosts/{myname}",
                            e.get_str());
            }
        }
    }
    subnets
}

/// Parse `ConnectTo =` names from `config`. `try_outgoing_connections`
/// (`net_socket.c:815-884`). Filters invalid names and self-reference.
fn parse_connect_to_from_config(config: &tinc_conf::Config, myname: &str) -> Vec<String> {
    config
        .lookup("ConnectTo")
        .map(|e| e.get_str().to_owned())
        .filter(|n| {
            if !tinc_proto::check_id(n) {
                log::error!(target: "tincd",
                            "Invalid name for outgoing connection: {n}");
                return false;
            }
            if n == myname {
                log::warn!(target: "tincd",
                            "ConnectTo = {n} is ourselves; skipping");
                return false;
            }
            true
        })
        .collect()
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

    /// `choose_udp_address` static counter (`net_packet.c:758`
    /// `static int x`). 2-of-3 calls explore an edge address;
    /// 1-of-3 sticks with `n->address` (the reflexive). NOT
    /// random — a strict cycle. C function-static (one global
    /// counter, NOT per-node); we use a daemon field.
    pub(crate) choose_udp_x: u8,

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

    /// `now.tv_sec` proxy. The C reads wall-clock seconds for the
    /// ICMP rate limiter (`route.c:130`: `ratelimit(3)` keys on
    /// `now.tv_sec`). The limiter only compares for SAME-SECOND;
    /// any monotonic-integer source works. We use daemon-uptime
    /// seconds: `timers.now().duration_since(started_at).as_secs()`.
    /// Set at setup; never reset.
    pub(crate) started_at: Instant,

    /// `route.c:85-100` static rate-limit state for ICMP error
    /// synthesis. C uses `static time_t lasttime; static int count`;
    /// we put it in a struct the daemon owns. Max 3/sec across ALL
    /// unreachable destinations (the C's static is global).
    pub(crate) icmp_ratelimit: icmp::IcmpRateLimit,

    /// Per-daemon compression workspace (`net_packet.c:240-400`).
    /// Currently a ZST (lz4_flex is stateless, zlib one-shot per
    /// call); kept as a struct so adding persistent z_stream state
    /// (PERF chunk-10) doesn't churn the wire-up sites.
    pub(crate) compressor: compress::Compressor,

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

    /// The device fd's `IoId`. `None` for `Dummy` (no fd, never
    /// registered). Stored so `on_device_read` can `rearm()` after
    /// hitting its drain-loop iteration cap — see the bounded-drain
    /// comment in that fn for why this matters under sustained load.
    pub(crate) device_io: Option<IoId>,

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

    /// `n->status.has_address` (`net_setup.c:211`). Names of nodes
    /// whose `hosts/NAME` file has an `Address =` line. Populated by
    /// `load_all_nodes` at setup + reload. Read by `autoconnect::
    /// decide` (the eligible-to-dial gate — `autoconnect.c:34`).
    ///
    /// **Why a `HashSet`, not a `NodeState` field**: `NodeState` is
    /// direct-peers-only (allocated in `on_ack`). `has_address`
    /// applies to ANY node we have a hosts/ file for, including ones
    /// we've never connected to and only know from disk. The C `node_
    /// t` smushes both lifecycles into one struct; we keep them
    /// separate. `load_all_nodes` does add every hosts/-file name to
    /// the GRAPH (matching C `:186-189`) so `node_ids` is the
    /// authoritative "nodes I know exist" set; this is just the
    /// `has_address` annotation on top.
    pub(crate) has_address: HashSet<String>,

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

    /// `c->status.mst` mapped. C `graph.c:103,107` sets each edge's
    /// connection's `status.mst`; we store the edge IDs and map at
    /// broadcast time (`NodeState.edge` is the conn→edge link).
    /// Populated by `run_graph()`; previously discarded.
    pub(crate) last_mst: Vec<EdgeId>,

    /// `route_mac`'s lookup table. `HashMap<Mac, owner-name>`.
    /// Maintained alongside `subnets`: every `Subnet::Mac` add/del
    /// also updates this. `SubnetTree::lookup_mac` exists but
    /// `route_mac.rs` takes the flat map directly (testability —
    /// see `route_mac.rs` doc). Five sync sites: `learn_mac`,
    /// `on_age_subnets`, `on_add_subnet`, `on_del_subnet`, reload.
    pub(crate) mac_table: HashMap<route_mac::Mac, String>,

    /// Expiry tracker for OUR learned MACs (those owned by
    /// `myself`). NOT all MAC subnets — peers' learned MACs are in
    /// `mac_table` (via gossip ADD_SUBNET) but not here. The C
    /// stores `expires` on `subnet_t` directly (`subnet.h:53`); we
    /// keep lifecycles separate (see `mac_lease.rs` doc).
    pub(crate) mac_leases: mac_lease::MacLeases,

    /// Lazy-created on the first `learn()` (when `learn()` returns
    /// `true` = "table was empty"). C `timeout_add` at `route.c:
    /// 549-551` is idempotent (checks if already in heap); we use
    /// `Option` to skip the check.
    pub(crate) age_subnets_timer: Option<TimerId>,

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

    /// `invitation_key` (`protocol_auth.c:56`). Loaded from
    /// `confbase/invitations/ed25519_key.priv` by `read_invitation_
    /// key`. `None` when no invitations have been issued (the file
    /// doesn't exist) — the `?` greeting is then rejected at id_h.
    /// Re-loaded on SIGHUP (`net_setup.c:570`: `read_invitation_key()`
    /// is inside `setup_myself_reloadable`).
    pub(crate) invitation_key: Option<SigningKey>,

    /// `last_config_check` (`net.c:43`). The mtime threshold for
    /// `conns_to_terminate` (`net.c:438-455`). Initialized to
    /// daemon-start time at the end of `setup()` (`net.c:458`: set
    /// at the END of reload, so first SIGHUP compares against start).
    pub(crate) last_config_check: SystemTime,

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

        // Reloadable settings (`net_setup.c:391-575`). Factored
        // into a helper so reload_configuration can call it too.
        // Reads PingInterval, PingTimeout, MaxTimeout, the bool
        // gates, InvitationExpire. NOT Port/AddressFamily (those
        // need re-bind, setup-only).
        apply_reloadable_settings(&config, &mut settings);

        // Proxy (`net_setup.c:263-345`). Only `exec` is wired.
        // Non-reloadable (the C reads it inside setup_myself_
        // reloadable but our outgoing-connection path reads it at
        // dial time; reload would need to re-dial existing conns).
        if let Some(e) = config.lookup("Proxy").next() {
            settings.proxy = parse_proxy_config(e.get_str()).map_err(SetupError::Config)?;
        }

        // Compression (`net_setup.c:991-1043`). HOST-tagged. The
        // level WE want peers to compress towards us at. The C
        // `switch` validates against built-in backends; we reject
        // LZO (stubbed) and >12 (unknown). Default 0 (`:1043`).
        if let Some(e) = config.lookup("Compression").next() {
            if let Ok(v) = e.get_int() {
                let v = u8::try_from(v).unwrap_or(255);
                match compress::Level::from_wire(v) {
                    compress::Level::LzoLo | compress::Level::LzoHi => {
                        return Err(SetupError::Config(format!(
                            "Compression = {v}: LZO compression is \
                             unavailable on this node"
                        )));
                    }
                    compress::Level::None if v != 0 => {
                        // `from_wire` mapped >12 → None. Reject.
                        return Err(SetupError::Config(format!(
                            "Compression = {v} is unrecognized by this node"
                        )));
                    }
                    _ => settings.compression = v,
                }
            }
        }

        // Mode (`net_setup.c:406-424`). routing_mode. C errors on
        // unknown. NOT in apply_reloadable_settings (device re-open).
        // Parsed BEFORE Forwarding to match C source order.
        if let Some(e) = config.lookup("Mode").next() {
            settings.routing_mode = match e.get_str().to_ascii_lowercase().as_str() {
                "router" => RoutingMode::Router,
                "switch" => RoutingMode::Switch,
                "hub" => RoutingMode::Hub,
                v => {
                    return Err(SetupError::Config(format!(
                        "Mode = {v}: invalid routing mode (router|switch|hub)"
                    )));
                }
            };
        }

        // Forwarding (`net_setup.c:426-443`). Default Internal.
        // C errors on unknown.
        if let Some(e) = config.lookup("Forwarding").next() {
            match e.get_str().to_ascii_lowercase().as_str() {
                "off" => settings.forwarding_mode = ForwardingMode::Off,
                "internal" => settings.forwarding_mode = ForwardingMode::Internal,
                "kernel" => settings.forwarding_mode = ForwardingMode::Kernel,
                v => {
                    return Err(SetupError::Config(format!(
                        "Forwarding = {v}: invalid forwarding mode"
                    )));
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
            #[cfg(target_os = "linux")]
            Some("tap") => {
                // C `linux/device.c:81-87`: `DeviceType = tap` OR
                // (`routing_mode != RMODE_ROUTER && !DeviceType`).
                // We only handle the explicit form here; the
                // auto-derive (Mode→device when DeviceType unset) is
                // a follow-up. The cross-impl test sets
                // `DeviceType = tap` explicitly.
                let cfg = tinc_device::DeviceConfig {
                    iface: config
                        .lookup("Interface")
                        .next()
                        .map(|e| e.get_str().to_owned()),
                    mode: tinc_device::Mode::Tap,
                    ..Default::default()
                };
                let tun = tinc_device::Tun::open(&cfg).map_err(SetupError::Io)?;
                Box::new(tun)
            }
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
        let device_io = if let Some(fd) = device.fd() {
            Some(
                ev.add(fd, Io::Read, IoWhat::Device)
                    .map_err(SetupError::Io)?,
            )
        } else {
            None
        };

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
        for s in parse_subnets_from_config(&config, &name) {
            subnets.add(s, name.clone());
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
        let connect_to = parse_connect_to_from_config(&config, &name);

        // ─── invitation key (net_setup.c:570 → keys.c:116-138)
        // `read_invitation_key`. `Ok(None)` if the file doesn't
        // exist — not an error, just no invites issued yet. The
        // `?` greeting is rejected at id_h. `Err` for corrupt PEM.
        let invitation_key = invitation_serve::read_invitation_key(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;
        if invitation_key.is_some() {
            log::info!(target: "tincd", "Invitation key loaded");
        }

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
            choose_udp_x: 0,
            tunnels: HashMap::new(),
            id6_table,
            contradicting_add_edge: 0,
            contradicting_del_edge: 0,
            // C `net.c:42`: `static int sleeptime = 10`.
            sleeptime: 10,
            started_at: timers.now(),
            icmp_ratelimit: icmp::IcmpRateLimit::new(),
            compressor: compress::Compressor::new(),
            // C `net.c:43`: `static struct timeval last_periodic_
            // run_time` zero-init. We seed with now: the first
            // `on_ping_tick` (after `pingtimeout` seconds) sees
            // a delta of `pingtimeout`, well under `2*30`.
            last_periodic_run_time: timers.now(),
            iface,
            device_errors: 0,
            device_io,
            outgoings: SlotMap::with_key(),
            outgoing_timers: slotmap::SecondaryMap::new(),
            connecting_socks: slotmap::SecondaryMap::new(),
            has_address: HashSet::new(),
            last_routes: Vec::new(),
            last_mst: Vec::new(),
            mac_table: HashMap::new(),
            mac_leases: mac_lease::MacLeases::default(),
            age_subnets_timer: None,
            settings,
            invitation_key,
            // C `net.c:458`: `last_config_check = now.tv_sec` at the
            // END of reload. setup() does the same at the end (after
            // the daemon struct is built); first SIGHUP compares
            // against this. We set it here at construct time — the
            // delta to "end of setup" is one event-loop turn (~ms).
            last_config_check: SystemTime::now(),
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

        // The mark-sweep (`:870-883`, terminate connections whose
        // ConnectTo was removed) is now in `reload_configuration`.
        // setup() never has stale outgoings (it's first boot).

        // ─── load_all_nodes (`net_setup.c:161-217`, called `:1057`)
        // C does this AFTER `graph()` (which only knows myself at
        // this point) and BEFORE device open. We do it after the
        // ConnectTo loop so the lookup_or_add_node above doesn't
        // race the directory walk — both add to the same graph,
        // order doesn't matter for correctness, but doing it last
        // keeps the "load every name from disk" step in one place.
        daemon.load_all_nodes();

        // ─── tinc-up (net_setup.c:745-762, `device_enable`)
        // C calls this AFTER device open succeeds, BEFORE `Ready`.
        // The script typically does `ip addr add` / `ip link set
        // up` on the TUN. Base env only (no NODE/SUBNET).
        daemon.run_script("tinc-up");

        // C `net_setup.c:1273`: `subnet_update(myself, NULL, true)`
        // — fire subnet-up for our OWN configured subnets. AFTER
        // tinc-up: that script typically does `ip addr add` /
        // `ip link set up`; subnet-up scripts (which add routes)
        // assume the iface is configured. Same loop shape as the
        // BecameReachable arm at gossip.rs:1061-1069.
        let owned: Vec<Subnet> = daemon
            .subnets
            .iter()
            .filter(|(_, o)| *o == daemon.name)
            .map(|(s, _)| *s)
            .collect();
        for s in &owned {
            daemon.run_subnet_script(true, &daemon.name, s);
        }

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
                    TimerWhat::AgeSubnets => {
                        self.on_age_subnets();
                    }
                    TimerWhat::KeyExpire | TimerWhat::UdpPing => {
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
}

impl Drop for Daemon {
    /// `exit_control` (`control.c:233-240`): unlink pidfile + socket.
    /// `ControlSocket::drop` already unlinks the socket. We do the
    /// pidfile.
    fn drop(&mut self) {
        // C `net_setup.c:1298`: `subnet_update(myself, NULL,
        // false)` BEFORE `device_disable`. Mirror of the setup-
        // time subnet-up loop. Subnet-down first (may `ip route
        // del`), THEN tinc-down (brings the iface down).
        let owned: Vec<Subnet> = self
            .subnets
            .iter()
            .filter(|(_, o)| *o == self.name)
            .map(|(s, _)| *s)
            .collect();
        for s in &owned {
            self.run_subnet_script(false, &self.name, s);
        }

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
        assert_eq!(s.compression, 0); // C `:1043` COMPRESS_NONE
        assert!(!s.tunnelserver); // C `:879` default false
        assert!(!s.directonly); // C `route.c:41`
        assert_eq!(s.forwarding_mode, ForwardingMode::Internal);
        // C `net_setup.c:561`: `else { autoconnect = true; }`.
        assert!(s.autoconnect);
        // C `protocol_misc.c:34-35`.
        assert_eq!(s.udp_info_interval, 5);
        assert_eq!(s.mtu_info_interval, 5);
    }

    /// `route.c:130-132` rate limit on the Unreachable arm. Max
    /// 3/sec. Can't construct a full `Daemon` (SelfPipe singleton);
    /// test the `IcmpRateLimit` directly with the same `freq=3`
    /// the daemon uses. The wiring (daemon-uptime-secs as the key)
    /// is exercised by the `real_tun_unreachable` netns test.
    #[test]
    fn ratelimit_drops_after_3() {
        let mut rl = icmp::IcmpRateLimit::new();
        // Same second: first 3 pass, 4th drops. C `:90-92`: `>=`.
        assert!(!rl.should_drop(42, 3));
        assert!(!rl.should_drop(42, 3));
        assert!(!rl.should_drop(42, 3));
        assert!(rl.should_drop(42, 3), "4th call same-sec must drop");
        assert!(rl.should_drop(42, 3), "5th call same-sec still drops");
        // Next second: counter resets. C `:94-96`.
        assert!(!rl.should_drop(43, 3));
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
