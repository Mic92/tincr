//! `Daemon` — the C globals as one struct, plus `main_loop()`.
//!
//! `net.c::main_loop` (`:487-527`): tick → turn → match. `IoWhat`
//! is the `W` in `EventLoop<W>` (six variants = six C io callbacks).
//! `run()` consumes `self`; teardown is `Drop`.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::inthash::IntHashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
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
    AddrFamily, Listener, MAXSOCKETS, SockOpts, Tarpit, configure_tcp, fmt_addr, is_local,
    open_listener_pair, open_listeners, pidfile_addr, unmap,
};
use crate::node_id::{NodeId6, NodeId6Table};
use crate::outgoing::{
    ConnectAttempt, MAX_TIMEOUT_DEFAULT, Outgoing, OutgoingId, ProxyConfig, parse_proxy_config,
    probe_connecting, resolve_config_addrs, try_connect, try_connect_via_proxy,
};
use crate::pmtu::{self, PmtuAction, PmtuState};
use crate::proto::{
    DispatchError, DispatchResult, IdCtx, IdOk, check_gate, handle_control, handle_id,
    myself_options_from_config, parse_ack, parse_add_edge, parse_add_subnet, parse_del_edge,
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
mod purge;
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
    /// `connection_t*`. Generational: stale id → `conns.get(id) == None`.
    /// C uses raw pointers + io_tree.generation guard.
    pub struct ConnId;
}

/// Per-peer runtime annotation. C `node_t` smushes topology +
/// runtime into one 200B struct; we split so `tinc-graph` stays
/// `#![no_std]`-clean.
#[derive(Debug, Clone)]
pub struct NodeState {
    /// `c->edge` (`ack_h:1051`). `terminate_connection` (`net.c:126`)
    /// deletes + broadcasts DEL_EDGE.
    pub edge: Option<EdgeId>,
    /// `n->connection`. None = known but not directly connected.
    pub conn: Option<ConnId>,
    /// `c->edge->address` (`ack_h:1024`). TCP addr, port rewritten to UDP.
    pub edge_addr: Option<SocketAddr>,
    /// `c->edge->weight` (`ack_h:1048`). Avg of RTTs, ms.
    pub edge_weight: i32,
    /// `c->edge->options` (`ack_h:996`). Top byte = peer's PROT_MINOR.
    pub edge_options: crate::proto::ConnOptions,
}

/// Six variants = six C `io_add` callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoWhat {
    /// `signalio_handler`.
    Signal,
    /// `handle_new_unix_connection`.
    UnixListener,
    /// `handle_device_data`. `Dummy.fd()` → None → never registered.
    Device,
    /// `handle_meta_io`.
    Conn(ConnId),
    /// `handle_new_meta_connection`. u8: MAXSOCKETS=16.
    Tcp(u8),
    /// `handle_incoming_vpn_data`.
    Udp(u8),
}

/// Seven C `timeout_add` callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerWhat {
    /// `timeout_handler` (`net.c:180`). +1s.
    Ping,
    /// `periodic_handler` (`net.c:268`). +5s.
    Periodic,
    /// `keyexpire_handler` (`net_setup.c:144-150`). +`keylifetime`s
    /// (default 3600). Forces SPTPS rekey on every active tunnel.
    KeyExpire,
    /// `age_past_requests` (`protocol.c:213-228`). +10s.
    AgePastRequests,
    /// `age_subnets` (`route.c:491-521`). +10s. Lazy-armed on first
    /// `learn_mac` (when `MacLeases::learn` returns true = empty).
    AgeSubnets,
    /// `retry_outgoing_handler`. C `outgoing_t.ev` (`net.h:123`).
    RetryOutgoing(OutgoingId),
    #[allow(dead_code)]
    UdpPing,
}

/// C registers 5 (`net.c:503-507`); TERM/QUIT/INT all map to Exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalWhat {
    /// SIGHUP → `sighup_handler`.
    Reload,
    /// SIGTERM/INT/QUIT → `sigterm_handler`.
    Exit,
    /// SIGALRM → `sigalrm_handler`.
    Retry,
}

// DaemonSettings — the config knobs

/// `setup_myself_reloadable` (`net_setup.c:252-575`). Separate from
/// `Daemon` so reload can swap it. `Default` matches C defaults.
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
    /// `:880`: `strictsubnets |= tunnelserver`. The implication is
    /// applied in `apply_reloadable_settings` after both are parsed.
    /// A tunnelserver hub doesn't gossip indirect topology AND
    /// doesn't trust direct peers to claim arbitrary subnets — they
    /// get exactly what's in their hosts/ file.
    pub tunnelserver: bool,
    /// `strictsubnets` (`net_setup.c:878`). Default false. The
    /// operator's `hosts/NAME` files become the AUTHORITY for which
    /// subnets each node owns. ADD_SUBNET gossip for subnets not in
    /// the file is ignored (forwarded, not added locally).
    /// DEL_SUBNET for subnets that ARE in the file is ignored.
    ///
    /// Predates `tunnelserver` and is implied by it (`:880`).
    /// `load_all_nodes` preloads the authorized subnets at startup;
    /// the `protocol_subnet.c:93` lookup-first means authorized
    /// gossip passes through silently (already-have-it noop).
    pub strictsubnets: bool,
    /// `directonly` (`net_setup.c:403`, `route.c:41`). Default
    /// false. Route-time gate: if `owner != via` (would relay),
    /// send ICMP `NET_ANO` instead. The relay path EXISTS and
    /// works; this knob lets the operator say "don't use it".
    pub directonly: bool,
    /// `priorityinheritance` (`net_setup.c:458`, `route.c:42`).
    /// Default false. Copy the inner packet's TOS/TC byte to the
    /// outer UDP socket via `IP_TOS`/`IPV6_TCLASS` before send.
    /// Without it, all encrypted traffic gets default DSCP
    /// regardless of inner QoS marking. C `route.c:669,765,1063`
    /// reads the byte; `net_packet.c:920-946` setsockopts.
    pub priorityinheritance: bool,
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
    /// `maxoutbufsize` (`net_setup.c:1255-1257`). Bytes. Default
    /// `10 * MTU` (=15180). The Random Early Drop threshold for the
    /// meta-connection TCP outbuf — under load, RED keeps the
    /// buffer from growing unbounded by probabilistically dropping
    /// data packets queued behind a slow TCP send.
    pub maxoutbufsize: usize,
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
    /// `BindToAddress` (`net_socket.c:624`). Default `None` (no
    /// bind — kernel picks the source addr from the route table).
    /// When set, outgoing meta-connections `bind()` to this local
    /// address before `connect()`. Useful for multi-homed hosts
    /// where the default route doesn't go via the desired interface.
    /// Config: `BindToAddress = HOST PORT` (port 0 = any).
    pub bind_to_address: Option<SocketAddr>,
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
    /// `keylifetime` (`net_setup.c:556-558`). Seconds. The KeyExpire
    /// timer fires at this interval and forces an SPTPS rekey on
    /// every tunnel with `validkey`. C default 3600.
    ///
    /// **Nonce-reuse guard.** SPTPS uses `outseqno: u32` as the
    /// ChaCha20-Poly1305 nonce. Neither C (`sptps.c:116,141`) nor
    /// Rust (`state.rs:403`) checks for wraparound. At 1.5 Gbps /
    /// 1400-byte packets (≈134k pps), 2^32 packets is ≈9 hours to
    /// nonce reuse — catastrophic for ChaCha20-Poly1305. The 3600s
    /// timer caps any single key at ≈4.8e8 packets, well clear.
    pub keylifetime: u32,
    /// Per-listener sockopts (`net_socket.c:41-46`). `UDPRcvBuf`/
    /// `UDPSndBuf`/`FWMark`/`BindToInterface` config keys. Non-
    /// reloadable: rebinding would mean closing all listeners.
    /// `fwmark` is also used by the outgoing-connect path
    /// (`net_socket.c:383` — separate site, not yet wired).
    pub sockopts: SockOpts,
    /// `scriptinterpreter` (`script.c:31`, set at `net_setup.c:237`
    /// via `ScriptsInterpreter`). When `Some`, scripts are run as
    /// `<interp> <script>` instead of `<script>` directly. Unix
    /// shebang makes this redundant; useful for shebang-less hooks
    /// or Windows (where shebang doesn't work). Default `None`.
    pub scripts_interpreter: Option<String>,
    /// `sptps_replaywin` (`sptps.c:33`, set at `net_setup.c:919`
    /// via `ReplayWindow`). Datagram-mode anti-replay window size
    /// in packets. C default 32 (`sptps.c:33`); the C `net_setup.c:
    /// 925-926` writes both `replaywin` (legacy) and `sptps_replaywin`
    /// from the one config key. Passed to every `Sptps::start`
    /// for UDP tunnels.
    pub replaywin: usize,
    /// `max_connection_burst` (`net_socket.c:45`, set at `:882`
    /// via `MaxConnectionBurst`). Tarpit leaky-bucket capacity.
    /// Same-host triggers at `> this`; all-host at `>= this`.
    /// C default 10. Non-reloadable: the tarpit is constructed
    /// once at setup.
    pub max_connection_burst: u32,
    /// `udp_discovery` (`net_packet.c:83`, set at `:395` via
    /// `UDPDiscovery`). Master switch for the UDP probe machinery.
    /// C default true. When false, `try_udp` is a no-op (`:1201`)
    /// and `try_mtu` skips the not-confirmed reset (`:1351`); the
    /// daemon falls back to TCP-only forwarding.
    pub udp_discovery: bool,
    /// `device_standby` (`net_setup.c:57`, set at `:1093` via
    /// `DeviceStandby`). Default false. When set, `tinc-up` is NOT
    /// fired at setup (`:1267`): the script defers until the FIRST
    /// peer becomes reachable (`graph.c:316`). Mirror for tinc-down:
    /// fired when the LAST peer becomes unreachable (`:314`). For
    /// laptops that don't want a configured-but-unconnected tun0
    /// hanging around. Non-reloadable.
    pub device_standby: bool,
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
            // C `net_setup.c:878`: default false.
            strictsubnets: false,
            // C `route.c:41`: `bool directonly = false`.
            directonly: false,
            // C `route.c:42`: `bool priorityinheritance = false`.
            priorityinheritance: false,
            // C `route.c:37`: `fmode_t forwarding_mode = FMODE_INTERNAL`.
            forwarding_mode: ForwardingMode::Internal,
            // C `route.c:39`: `routing_mode = RMODE_ROUTER`.
            routing_mode: RoutingMode::Router,
            // C `net_setup.c:883`: `bcast_mode = BMODE_MST`.
            broadcast_mode: broadcast::BroadcastMode::Mst,
            // C `route.c:43`: `int macexpire = 600`.
            macexpire: mac_lease::DEFAULT_EXPIRE_SECS,
            // C `net_setup.c:1257`: `maxoutbufsize = 10 * MTU`.
            maxoutbufsize: 10 * MTU as usize,
            // C `net_setup.c:567`: `invitation_lifetime = 604800` (1 week).
            invitation_lifetime: Duration::from_secs(604_800),
            // C `net_setup.c:404`: default false (no `else` branch).
            local_discovery: false,
            // C `net_socket.c:624`: only set if config present.
            bind_to_address: None,
            proxy: None,
            // C `net_setup.c:561`: `else { autoconnect = true; }`.
            autoconnect: true,
            // C `protocol_misc.c:35`: `int udp_info_interval = 5`.
            udp_info_interval: 5,
            // C `protocol_misc.c:34`: `int mtu_info_interval = 5`.
            mtu_info_interval: 5,
            // C `net_setup.c:558`: `keylifetime = 3600`.
            keylifetime: 3600,
            // C `net_socket.c:41-46`: globals with initializers.
            sockopts: SockOpts::default(),
            // C `script.c:31`: `char *scriptinterpreter = NULL`.
            scripts_interpreter: None,
            // C `sptps.c:33`: `unsigned int sptps_replaywin = 32`.
            // (Our gossip.rs hardcoded 16 — a bug; C is 32.)
            replaywin: 32,
            // C `net_socket.c:45`: `int max_connection_burst = 10`.
            max_connection_burst: 10,
            // C `net_packet.c:83`: `bool udp_discovery = true`.
            udp_discovery: true,
            // C `net_setup.c:57`: `bool device_standby = false`.
            device_standby: false,
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
#[allow(clippy::too_many_lines)] // straight-line config-var parse
fn apply_reloadable_settings(config: &tinc_conf::Config, settings: &mut DaemonSettings) {
    // PingInterval (`:1241-1243`).
    if let Some(e) = config.lookup("PingInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.pinginterval = v;
    }
    // PingTimeout (`:1247-1253`). Clamped to [1, pinginterval].
    if let Some(e) = config.lookup("PingTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.pingtimeout = v.clamp(1, settings.pinginterval);
    }
    // MaxTimeout (`:527-533`).
    if let Some(e) = config.lookup("MaxTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.maxtimeout = v;
    }
    // DecrementTTL (`:457`).
    if let Some(e) = config.lookup("DecrementTTL").next()
        && let Ok(v) = e.get_bool()
    {
        settings.decrement_ttl = v;
    }
    // TunnelServer (`:879`).
    if let Some(e) = config.lookup("TunnelServer").next()
        && let Ok(v) = e.get_bool()
    {
        settings.tunnelserver = v;
    }
    // StrictSubnets (`:878`).
    if let Some(e) = config.lookup("StrictSubnets").next()
        && let Ok(v) = e.get_bool()
    {
        settings.strictsubnets = v;
    }
    // C `:880`: `strictsubnets |= tunnelserver`. After BOTH parsed.
    settings.strictsubnets |= settings.tunnelserver;
    // LocalDiscovery (`:404`).
    if let Some(e) = config.lookup("LocalDiscovery").next()
        && let Ok(v) = e.get_bool()
    {
        settings.local_discovery = v;
    }
    // DirectOnly (`:403`).
    if let Some(e) = config.lookup("DirectOnly").next()
        && let Ok(v) = e.get_bool()
    {
        settings.directonly = v;
    }
    // PriorityInheritance (`:458`).
    if let Some(e) = config.lookup("PriorityInheritance").next()
        && let Ok(v) = e.get_bool()
    {
        settings.priorityinheritance = v;
    }
    // AutoConnect (`:560-562`). Default true — keep the default if
    // the parse fails (C `get_config_bool` only writes on success).
    if let Some(e) = config.lookup("AutoConnect").next()
        && let Ok(v) = e.get_bool()
    {
        settings.autoconnect = v;
    }
    // ScriptsInterpreter (`net_setup.c:237`). C `read_interpreter`
    // also has a sandbox-guard (`:239-243`: don't change interp
    // mid-run if sandboxed); we don't sandbox, so just read it.
    // ScriptsExtension (`:257`) is NOT parsed: on Unix the C
    // default is "" (`names.c`) and `script.rs::execute` doesn't
    // append a suffix. Windows-only knob; we'd compile_error there.
    settings.scripts_interpreter = config
        .lookup("ScriptsInterpreter")
        .next()
        .map(|e| e.get_str().to_owned());
    // UDPDiscovery* (`net_setup.c:395-398`). bool + 3 intervals.
    if let Some(e) = config.lookup("UDPDiscovery").next()
        && let Ok(v) = e.get_bool()
    {
        settings.udp_discovery = v;
    }
    if let Some(e) = config.lookup("UDPDiscoveryKeepaliveInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_discovery_keepalive_interval = v;
    }
    if let Some(e) = config.lookup("UDPDiscoveryInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_discovery_interval = v;
    }
    if let Some(e) = config.lookup("UDPDiscoveryTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_discovery_timeout = v;
    }
    // MaxConnectionBurst (`net_setup.c:882-886`). C errors on <=0;
    // we silently keep default (less harsh on reload typo).
    if let Some(e) = config.lookup("MaxConnectionBurst").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.max_connection_burst = v;
    }
    // ReplayWindow (`net_setup.c:919-926`). C errors on <0; the
    // unsigned try_from rejects that. C also writes legacy
    // `replaywin`; we're SPTPS-only so just `sptps_replaywin`.
    if let Some(e) = config.lookup("ReplayWindow").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = usize::try_from(v)
    {
        settings.replaywin = v;
    }
    // UDPInfoInterval / MTUInfoInterval (`:400-401`).
    if let Some(e) = config.lookup("UDPInfoInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.udp_info_interval = v;
    }
    if let Some(e) = config.lookup("MTUInfoInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.mtu_info_interval = v;
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
    if let Some(e) = config.lookup("MACExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u64::try_from(v)
    {
        settings.macexpire = v;
    }
    // MaxOutputBufferSize (`net_setup.c:1255-1257`).
    if let Some(e) = config.lookup("MaxOutputBufferSize").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = usize::try_from(v)
    {
        settings.maxoutbufsize = v;
    }
    // InvitationExpire (`:566-568`).
    if let Some(e) = config.lookup("InvitationExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u64::try_from(v)
    {
        settings.invitation_lifetime = Duration::from_secs(v);
    }
    // KeyExpire (`:556-558`).
    if let Some(e) = config.lookup("KeyExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.keylifetime = v;
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

/// Parse `BindToAddress` / `ListenAddress` value: `"HOST [PORT]"`.
/// C `add_listen_address:639-649`: split on first space; port half
/// is optional (defaults to global `Port`). C `:649`: `"*"` means
/// the wildcard (any address) — maps to an empty host so
/// `to_socket_addrs` sees `("", port)` → fails → caller falls back
/// to `open_listeners` (the wildcard path). We instead translate
/// `*` to the literal wildcard IP per the requested family in
/// `build_listeners` (simpler than threading the empty-host case).
fn parse_bind_addr(s: &str, default_port: u16) -> (&str, u16) {
    let mut parts = s.splitn(2, ' ');
    let host = parts.next().unwrap_or("");
    // C uses string `port`; getaddrinfo resolves service names.
    // We only accept numeric (matching `Port` parsing above).
    let port = parts
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    (host, port)
}

/// `add_listen_address` walk (`net_setup.c:1155-1177`). For each
/// `BindToAddress` line then each `ListenAddress` line, resolve and
/// create listener pair(s). If neither key is present, fall through
/// to the wildcard default (`open_listeners`).
///
/// Port reuse (`net_setup.c:700,710`): the first listener picks an
/// ephemeral with `Port=0`; every subsequent bind tries to reuse it
/// so the daemon advertises ONE port to peers regardless of how many
/// addresses it's listening on.
///
/// `bindto` distinguishes the two config keys (`:1160` vs `:1169`):
/// `BindToAddress` listeners are also used as outgoing-connect source
/// addresses; `ListenAddress` listeners are listen-only.
fn build_listeners(
    config: &tinc_conf::Config,
    port: u16,
    family: AddrFamily,
    opts: &SockOpts,
) -> Vec<Listener> {
    let mut listeners: Vec<Listener> = Vec::new();
    // C `:700`: `from_fd = listen_socket[0].tcp.fd`. We carry the
    // port directly. None until the first successful bind.
    let mut reuse_port: Option<u16> = if port == 0 { None } else { Some(port) };
    // C `:1154`: `int cfgs = 0` — did we see ANY config line?
    let mut cfgs = 0usize;
    // C `:686-693` dedups against `listen_socket[i].sa` which holds
    // the REQUESTED `aip->ai_addr` (port 0 and all — `:734` memcpy
    // happens before any port readback). We can't compare against
    // `l.local` (that's post-bind, ephemeral filled in); track the
    // pre-bind resolved addrs separately.
    let mut requested: Vec<SocketAddr> = Vec::new();

    // Inner per-address bind. Mirrors the body of the C
    // `for(aip = ai; aip; aip = aip->ai_next)` loop at `:679-736`.
    let mut try_addr = |addr: SocketAddr, bindto: bool| {
        // C `:686-693`: skip duplicates. memcmp on the addrinfo
        // sockaddr, BEFORE bind_reusing_port runs.
        if requested.contains(&addr) {
            return;
        }
        requested.push(addr);
        // C `:695-699`: MAXSOCKETS cap. Warn-and-stop, not error.
        if listeners.len() >= MAXSOCKETS {
            log::error!(target: "tincd::net", "Too many listening sockets");
            return;
        }
        if let Some(l) = open_listener_pair(addr, opts, reuse_port, bindto) {
            // C `:710`: first successful bind seeds the reuse port.
            // Only meaningful when `Port=0` (otherwise reuse_port
            // was already Some(port)).
            if reuse_port.is_none() {
                reuse_port = Some(l.local.port());
            }
            listeners.push(l);
        }
    };

    // C `:1156-1162`: `for(cfg = lookup("BindToAddress"); ...)`.
    // `bindto = true`.
    for (key, bindto) in [("BindToAddress", true), ("ListenAddress", false)] {
        for e in config.lookup(key) {
            cfgs += 1;
            let s = e.get_str();
            let (host, p) = parse_bind_addr(s, port);
            // C `:649`: `"*"` → NULL → getaddrinfo wildcard. We
            // synthesize the wildcard addrs directly (same outcome,
            // skips the resolver).
            if host == "*" {
                if family.try_v4() {
                    try_addr((std::net::Ipv4Addr::UNSPECIFIED, p).into(), bindto);
                }
                if family.try_v6() {
                    try_addr((std::net::Ipv6Addr::UNSPECIFIED, p).into(), bindto);
                }
                continue;
            }
            // C `:669`: `getaddrinfo(host, port, AI_PASSIVE)`.
            // `to_socket_addrs` is the same syscall. A hostname may
            // resolve to multiple addrs (v4+v6); bind each.
            match (host, p).to_socket_addrs() {
                Ok(iter) => {
                    for addr in iter {
                        // C `:657`: `hint.ai_family = addressfamily`.
                        // getaddrinfo would filter; to_socket_addrs
                        // doesn't take a family hint, so filter here.
                        let ok = match family {
                            AddrFamily::Any => true,
                            AddrFamily::Ipv4 => addr.is_ipv4(),
                            AddrFamily::Ipv6 => addr.is_ipv6(),
                        };
                        if ok {
                            try_addr(addr, bindto);
                        }
                    }
                }
                Err(e) => {
                    // C `:673-677`: getaddrinfo error → log + return
                    // false (which `setup_network` propagates as
                    // fatal). We're more lenient: skip this entry,
                    // try the rest. If ALL fail, the empty-listeners
                    // check below catches it.
                    log::error!(target: "tincd::net",
                                "{key} = {s}: {e}");
                }
            }
        }
    }

    // C `:1173`: `if(!cfgs) add_listen_address(NULL, NULL)` — the
    // no-config wildcard default.
    if cfgs == 0 {
        return open_listeners(port, family, opts);
    }

    listeners
}

/// `get_name()` $-expansion (`net_setup.c:220-233`).
///
/// `Name = $FOO` reads env var `FOO`. `Name = $HOST` falls back to
/// `gethostname(2)` truncated at the first `.` when the env var is
/// unset (the C special case). The result is sanitized: any non-alnum
/// char becomes `_`, so a hostname like `my-host` is a valid node
/// name. Sanitize-then-check_id is the C order.
///
/// Names without a `$` prefix are returned unchanged (NOT sanitized;
/// the C only sanitizes the env branch).
#[allow(unsafe_code)] // libc::gethostname; nix `hostname` feature not enabled
fn expand_name(name: &str) -> Result<String, String> {
    let Some(var) = name.strip_prefix('$') else {
        return Ok(name.to_owned());
    };

    let raw = match std::env::var(var) {
        Ok(v) => v,
        Err(_) if var == "HOST" => {
            // C: `gethostname(hostname, sizeof(hostname))` then
            // `hostname[31] = 0`. 32-byte buf is the C limit; we keep it.
            let mut buf = [0u8; 32];
            // SAFETY: buf is valid, len is correct. gethostname(2)
            // writes a NUL-terminated string (POSIX leaves truncation
            // unspecified — we force-NUL the last byte like C does).
            let rc =
                unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
            if rc != 0 {
                return Err(format!(
                    "gethostname failed: {}",
                    io::Error::last_os_error()
                ));
            }
            buf[31] = 0;
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            // C: `if(dot) *dot = 0;` — strip domain part.
            let dot = buf[..nul].iter().position(|&b| b == b'.').unwrap_or(nul);
            String::from_utf8_lossy(&buf[..dot]).into_owned()
        }
        Err(_) => {
            return Err(format!(
                "Invalid Name: environment variable {var} does not exist"
            ));
        }
    };

    // C: `for(char *c = name; *c; c++) if(!isalnum(*c)) *c = '_';`
    Ok(raw
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect())
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

/// Daemon-side wrapper around `Listener`. Bundles the event-loop
/// `IoId` (for UDP rearm after a `recvmmsg` batch cap; bug audit
/// `deef1268`) and the last `IP_TOS`/`IPV6_TCLASS` set on the UDP
/// socket (`listen_socket[sock].priority`, `net_packet.c:921`; only
/// `setsockopt` when changed). Kept here, not on `Listener`, so
/// `listen.rs` stays event-loop-agnostic.
pub(crate) struct ListenerSlot {
    pub(crate) listener: Listener,
    pub(crate) udp_io: IoId,
    pub(crate) last_tos: u8,
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
    pub(crate) listeners: Vec<ListenerSlot>,

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
    /// setup.c:383-453,800`). Built from global `IndirectData`/
    /// `TCPOnly`/`PMTUDiscovery`/`ClampMSS` at `setup()`.
    pub(crate) myself_options: crate::proto::ConnOptions,

    /// `myport.udp`. C string (`net_setup.c:54,794`); we store the
    /// resolved u16. Read back from `listeners[0].udp_port()` after
    /// bind (the C does the same at `:1194` `get_bound_port`).
    /// `bind_reusing_port` makes UDP follow TCP's ephemeral with
    /// `Port = 0`, so this equals `listeners[0].local.port()`.
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
    ///
    /// Keyed by `NodeId` (not `String`). Same monotonic-node
    /// proof as `node_log_name`: tincd never calls `Graph::
    /// del_node`, so any `NodeId` from `node_ids` / `id6_table` /
    /// edge endpoints / `last_routes` is always live. Keying by
    /// the `Copy` ID kills the `graph.node(nid).name → nodes.
    /// get(name)` double-lookup at every per-packet site.
    pub(crate) nodes: IntHashMap<NodeId, NodeState>,

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
    pub(crate) tunnels: IntHashMap<NodeId, TunnelState>,

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

    /// Reused send-side scratch for the UDP data path. `seal_data_into`
    /// writes `[0;12] ‖ SPTPS-datagram` here; `send_sptps_data_relay`
    /// then overwrites the 12-byte prefix with `[dst_id6 ‖ src_id6]`
    /// in-place and `sendto`s the whole thing. Cleared (not freed)
    /// between packets — after the first packet at MTU, capacity is
    /// `12 + MTU + 21` and stays there. Net: zero allocs on the
    /// per-packet send path. C `vpn_packet_t` (`net.h:62-87`) does
    /// the same with a stack arena; we can't VLA in Rust, so a
    /// daemon-owned Vec is the closest equivalent.
    pub(crate) tx_scratch: Vec<u8>,

    /// `vpn_packet_t.priority` (`net.h:84`). Inner-packet TOS set
    /// by `route_packet` (`route.c:669,765,1063`), read by the UDP
    /// send path (`net_packet.c:831,920`). C threads it via the
    /// packet struct; we don't have one, but the daemon is single-
    /// threaded so a field works. Reset to 0 at the top of each
    /// `route_packet` (matches C `:1921,1076,1190`).
    pub(crate) tx_priority: u8,

    /// Reused recv-side scratch for the UDP data path. Mirror of
    /// `tx_scratch`. `open_data_into` writes `[0;14] ‖ decrypted-body`
    /// here; `receive_sptps_record_fast` then overwrites `[12..14]` with
    /// the synthesized ethertype in-place and routes the whole slice.
    /// Cleared (not freed) between packets — after the first packet at
    /// MTU, capacity is `14 + MTU` and stays there. Net: zero allocs on
    /// the per-packet receive path.
    pub(crate) rx_scratch: Vec<u8>,

    /// recvmmsg batch state (`net_packet.c:1845-1895`). C uses
    /// `static vpn_packet_t pkt[64]` + `static struct mmsghdr msg[64]`
    /// (~108KB, program lifetime). We heap-allocate once at setup.
    /// `Option` so `on_udp_recv` can `mem::take` it (the bufs borrow
    /// fights `&mut self` for `handle_incoming_vpn_packet`; same
    /// dance as `rx_scratch` in `e49b5af6`).
    pub(crate) udp_rx_batch: Option<net::UdpRxBatch>,

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

    /// `overwrite_mac` (`route.c:44`). Derived, NOT a config var:
    /// `(device emits full eth frames) && (Mode=router)`. C sets it
    /// in each device backend's setup (`linux/device.c:82`, `bsd/
    /// device.c:337`, `vde_device.c:70`, `windows/device.c:229`,
    /// `linux/uml_device.c:160`). Router-mode IGNORES MACs but the
    /// kernel doesn't — a TAP write with zero dst-MAC is dropped by
    /// the rx filter. Fix: snatch the kernel's MAC from its own
    /// ARP/NDP solicits, stamp it onto outgoing frames. See `mymac`.
    pub(crate) overwrite_mac: bool,

    /// `mymac` (`route.c:45`). The kernel's interface MAC. C init:
    /// `{0xFE,0xFD,0,0,0,0}` (locally-administered placeholder).
    /// On Linux TAP, `SIOCGIFHWADDR` (`device.mac()`) seeds it at
    /// setup; on BSD TAP, `SIOCGIFADDR` (`bsd/device.c:369`). Then
    /// REFRESHED on every ARP/NDP from the kernel (`route.c:830,
    /// 971`) — the eth-src of those frames IS the kernel's MAC.
    /// Read at `net_packet.c:1557-1562` (the stamp).
    pub(crate) mymac: [u8; 6],

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

    /// Tracks whether `device_enable()` (tinc-up) has fired.
    /// `graph.c:313-319`: when `device_standby`, tinc-up fires on
    /// first reachable peer, tinc-down on last unreachable. This
    /// bool prevents double-fire (C doesn't have it; the C guard
    /// is the `reachable_count == became_reachable_count` arithmetic
    /// at `:316` which is exact, but we're processing transitions
    /// one-by-one not in a batch — simpler to track explicitly).
    pub(crate) device_enabled: bool,

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
    /// `keyexpire_handler` (`net_setup.c:144`). Re-arms +`keylifetime`.
    pub(crate) keyexpire_timer: TimerId,

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
    /// Node name for logging. tincd never calls `Graph::del_node`
    /// (only `del_edge`; nodes accumulate monotonically), so any
    /// `NodeId` obtained from `node_ids`, `id6_table`, `last_routes`,
    /// or an `Edge`'s endpoints is always live. The `<gone>`
    /// fallback never fires — it exists because `Graph::node`
    /// returns `Option` (the graph crate doesn't know tincd's
    /// monotonic-node usage). Helper consolidates 11 callsites that
    /// previously open-coded the `map_or`.
    pub(super) fn node_log_name(&self, nid: NodeId) -> &str {
        self.graph.node(nid).map_or("<gone>", |n| n.name.as_str())
    }

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
    pub fn setup(
        confbase: &Path,
        pidfile: &Path,
        socket: &Path,
        cmdline_conf: &tinc_conf::Config,
    ) -> Result<Self, SetupError> {
        // ─── read tinc.conf (tincd.c:590)
        let mut config = tinc_conf::read_server_config(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;

        // ─── cmdline -o overrides (conf.c:read_server_config does
        // `read_config_options(tree, NULL)` BEFORE reading tinc.conf,
        // but the merge order is irrelevant: `Source::Cmdline` sorts
        // before `Source::File` in the 4-tuple compare regardless of
        // when it's inserted. Merging after is simpler — main.rs owns
        // the cmdline list, this fn doesn't reach for a global).
        //
        // Empty `cmdline_conf` (no `-o` given) is a no-op merge.
        // Tests pass `Config::new()`.
        config.merge(cmdline_conf.entries().iter().cloned());

        // ─── Name (net_setup.c:775-779)
        // C: `name = get_name(); if(!name) { ERR }`.
        // `get_name()` does `lookup_config("Name")` + `$`-expansion
        // (`net_setup.c:220-233`, see `expand_name`) + `check_id`.
        // Skeleton: just lookup. `check_id` (alphanumeric + `_`)
        // is the right validation but tinc-tools/names.rs has it,
        // not tinc-conf — and we don't dep on tinc-tools. Chunk 3+
        // hoists `check_id` to a shared place (probably tinc-proto;
        // it's wire-format-adjacent).
        let name = config
            .lookup("Name")
            .next()
            .map(tinc_conf::Entry::get_str)
            .ok_or(SetupError::Config("Name for tinc daemon required!".into()))?;
        let name = expand_name(name).map_err(SetupError::Config)?;
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

        // BindToAddress (`net_socket.c:624` for outgoing source-
        // addr selection). Non-reloadable. Same `host port` shape
        // as `Address`. We only stash the FIRST entry here for the
        // outgoing-connect bind — the C uses listener[].sa filtered
        // by `bindto` for that, but our outgoing path predates the
        // listener walk and takes a single Option<SocketAddr>.
        // The FULL set of BindToAddress entries is re-read below
        // in the listener-creation block (the config tree is still
        // alive).
        if let Some(e) = config.lookup("BindToAddress").next() {
            let s = e.get_str();
            let (host, port) = parse_bind_addr(s, 0);
            // `to_socket_addrs()` for hostname → IP. The C uses
            // `str2addrinfo` (`netutl.c:87`); same getaddrinfo call.
            // Take the first result (the C does too — `*ai = ai[0]`).
            match (host, port).to_socket_addrs() {
                Ok(mut iter) => settings.bind_to_address = iter.next(),
                Err(e) => {
                    log::warn!(target: "tincd",
                               "BindToAddress = {s}: {e}; not binding");
                }
            }
        }

        // UDPRcvBuf / UDPSndBuf (`net_setup.c:889-904`). C rejects
        // negative; we get that for free from the usize parse. C
        // sets `udp_{rcv,snd}buf_warnings = true` ONLY when the
        // operator explicitly configures — the 1MB default tripping
        // the kernel cap on every boot would be log noise.
        if let Some(e) = config.lookup("UDPRcvBuf").next()
            && let Ok(v) = e.get_int()
        {
            match usize::try_from(v) {
                Ok(v) => {
                    settings.sockopts.udp_rcvbuf = v;
                    settings.sockopts.udp_buf_warnings = true;
                }
                Err(_) => {
                    return Err(SetupError::Config("UDPRcvBuf cannot be negative!".into()));
                }
            }
        }
        if let Some(e) = config.lookup("UDPSndBuf").next()
            && let Ok(v) = e.get_int()
        {
            match usize::try_from(v) {
                Ok(v) => {
                    settings.sockopts.udp_sndbuf = v;
                    settings.sockopts.udp_buf_warnings = true;
                }
                Err(_) => {
                    return Err(SetupError::Config("UDPSndBuf cannot be negative!".into()));
                }
            }
        }

        // FWMark (`net_setup.c:907-912`). C `get_config_int` into
        // `int fwmark`; 0 (default/unset) means "skip". The C has
        // an `#ifndef SO_MARK` warning at `:910` for non-Linux —
        // we're Linux-only for now so the gate is implicit.
        if let Some(e) = config.lookup("FWMark").next()
            && let Ok(v) = e.get_int()
            && let Ok(v) = u32::try_from(v)
        {
            settings.sockopts.fwmark = v;
        }

        // BindToInterface (`net_socket.c:111-142`). The C reads
        // this LAZILY inside `bind_to_interface()` per-socket; we
        // hoist the config read to setup-time. Same effect: it's
        // not reloadable either way (sockets are already bound).
        if let Some(e) = config.lookup("BindToInterface").next() {
            settings.sockopts.bind_to_interface = Some(e.get_str().to_owned());
        }

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
        if let Some(e) = config.lookup("Compression").next()
            && let Ok(v) = e.get_int()
        {
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

        // DeviceStandby (`net_setup.c:1093`). Non-reloadable: it
        // decides whether tinc-up fires at setup vs first-peer.
        if let Some(e) = config.lookup("DeviceStandby").next()
            && let Ok(v) = e.get_bool()
        {
            settings.device_standby = v;
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
        let device_mode = device.mode();
        log::info!(target: "tincd",
                   "Device mode: {device_mode:?}, interface: {iface}");

        // C `linux/device.c:82` (and bsd/vde/uml/windows): TAP-ish
        // device + Mode=router → the kernel emits/expects eth frames
        // but our routing layer ignores MACs. The stamp (`net_packet.c:
        // 1557-1562`) writes a valid dst-MAC on the way to the device.
        let overwrite_mac =
            device_mode == tinc_device::Mode::Tap && settings.routing_mode == RoutingMode::Router;
        // C `route.c:45`: `{0xFE,0xFD,0,0,0,0}` placeholder. C `bsd/
        // device.c:369` (and Linux TAP via SIOCGIFHWADDR) seeds from
        // the kernel; the ARP/NDP snatch then keeps it fresh.
        let mymac = device.mac().unwrap_or([0xFE, 0xFD, 0, 0, 0, 0]);

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

        // ─── keyexpire timer (net_setup.c:1049-1051)
        // C: `timeout_add(&keyexpire_timeout, keyexpire_handler, ...,
        // { keylifetime, jitter() })`. The handler (`:144-150`) calls
        // `regenerate_key()` then re-arms +keylifetime. C-nolegacy
        // never arms this (the timeout_add is `#ifndef DISABLE_
        // LEGACY`); that's a C bug — SPTPS still needs the rekey to
        // bound the ChaCha20 nonce counter. We arm unconditionally.
        let keyexpire_timer = timers.add(TimerWhat::KeyExpire);
        timers.set(
            keyexpire_timer,
            Duration::from_secs(u64::from(settings.keylifetime)),
        );

        // ─── listeners (net_setup.c:1152-1183)
        // C: walk BindToAddress configs, then ListenAddress configs,
        // else `add_listen_address(NULL, NULL)` for the no-config
        // default. Each `add_listen_address` resolves a hostname and
        // creates one TCP+UDP pair per resolved address.
        //
        // C `:1180`: `if(!listen_sockets) { ERR; return false }`.
        // Hard error. The daemon can't function without at least one
        // listener (peers can't connect; we can't receive UDP).
        let listeners = build_listeners(
            &config,
            settings.port,
            settings.addressfamily,
            &settings.sockopts,
        );
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
        // C `control.c:155-176`: get listeners[0]'s bound addr, map
        // 0.0.0.0→127.0.0.1, format `"HOST port PORT"`. The CLI on
        // Windows (no unix socket) actually CONNECTS to this addr.
        // On Unix the CLI uses the unix socket and ignores the addr,
        // but the pidfile format is fixed. Computed here, before
        // `listeners` is consumed into `ListenerSlot`s.
        let address = pidfile_addr(&listeners);
        // Register each pair. C `:723-724`: `io_add(&sock->tcp, ...)`.
        // The index `i` becomes `IoWhat::Tcp(i)` so the dispatch arm
        // can index back into `listeners[i]` for the accept.
        let mut listener_slots = Vec::with_capacity(listeners.len());
        for (i, l) in listeners.into_iter().enumerate() {
            let (tcp_fd, udp_fd) = l.fds();
            // u8 cast: MAXSOCKETS=8 fits trivially. The C uses int.
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u8;
            ev.add(tcp_fd, Io::Read, IoWhat::Tcp(i))
                .map_err(SetupError::Io)?;
            let udp_io = ev
                .add(udp_fd, Io::Read, IoWhat::Udp(i))
                .map_err(SetupError::Io)?;
            listener_slots.push(ListenerSlot {
                listener: l,
                udp_io,
                last_tos: 0,
            });
        }

        // ─── init_control (net_setup.c:1263, control.c:148-231)
        let cookie = generate_cookie();
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

        // ─── BroadcastSubnet (net_setup.c:485-505)
        // C: hard-coded `ff:ff:ff:ff:ff:ff`, `255.255.255.255`,
        // `224.0.0.0/4`, `ff00::/8` inserted with `subnet_add(NULL,
        // s)`, then walk `BroadcastSubnet` config keys (also NULL
        // owner). `route.c:644,738`: ownerless → `route_broadcast`.
        // Without these, kernel multicast (mDNS, NDP, DHCP) read
        // from TUN hit Unreachable{NET_UNKNOWN} and we ICMP-bounce
        // our own kernel. Silent breakage — mDNS doesn't surface
        // ICMP. (`Mode = switch` unaffected: route_mac floods on
        // miss anyway.)
        for s in [
            "ff:ff:ff:ff:ff:ff",
            "255.255.255.255",
            "224.0.0.0/4",
            "ff00::/8",
        ] {
            // C `:489`: `if(!str2net(...)) abort()`. These literals
            // are correct by construction; expect() is the abort.
            subnets.add_broadcast(s.parse().expect("hard-coded broadcast subnet"));
        }
        // C `:497-505`: walk multi-valued config key.
        for e in config.lookup("BroadcastSubnet") {
            match e.get_str().parse::<Subnet>() {
                Ok(s) => subnets.add_broadcast(s),
                Err(_) => {
                    // C `:500`: `if(!get_config_subnet(...)) continue`.
                    log::error!(target: "tincd",
                                "Invalid BroadcastSubnet = {}", e.get_str());
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
            listeners: listener_slots,
            // Tarpit::new wants a now seed (avoids the C's `static
            // time_t = 0` first-tick bug). Use the cached now.
            tarpit: Tarpit::new(timers.now(), settings.max_connection_burst),
            cookie,
            pidfile: pidfile.to_path_buf(),
            name,
            mykey,
            confbase: confbase.to_path_buf(),
            myself_options: myself_options_from_config(&config),
            my_udp_port,
            graph,
            node_ids,
            myself,
            subnets,
            seen: SeenRequests::new(),
            nodes: IntHashMap::default(),
            edge_addrs: HashMap::new(),
            choose_udp_x: 0,
            tunnels: IntHashMap::default(),
            id6_table,
            contradicting_add_edge: 0,
            contradicting_del_edge: 0,
            // C `net.c:42`: `static int sleeptime = 10`.
            sleeptime: 10,
            started_at: timers.now(),
            icmp_ratelimit: icmp::IcmpRateLimit::new(),
            compressor: compress::Compressor::new(),
            tx_priority: 0,
            tx_scratch: Vec::with_capacity(
                12 + usize::from(crate::tunnel::MTU) + tinc_sptps::DATAGRAM_OVERHEAD,
            ),
            rx_scratch: Vec::with_capacity(14 + usize::from(crate::tunnel::MTU)),
            udp_rx_batch: Some(net::UdpRxBatch::new()),
            // C `net.c:43`: `static struct timeval last_periodic_
            // run_time` zero-init. We seed with now: the first
            // `on_ping_tick` (after `pingtimeout` seconds) sees
            // a delta of `pingtimeout`, well under `2*30`.
            last_periodic_run_time: timers.now(),
            iface,
            overwrite_mac,
            mymac,
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
            // Set true by `device_enable()` after this struct is
            // built (when `!device_standby`); else false until the
            // first BecameReachable.
            device_enabled: false,
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
            keyexpire_timer,
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
        // C `:1267`: `if(!device_standby) device_enable()`. When
        // standby, the FIRST BecameReachable in `run_graph_and_log`
        // fires it instead (`graph.c:316`).
        if !daemon.settings.device_standby {
            daemon.device_enable();
        }

        // C `net_setup.c:1273`: `subnet_update(myself, NULL, true)`
        // — fire subnet-up for our OWN configured subnets. AFTER
        // tinc-up: that script typically does `ip addr add` /
        // `ip link set up`; subnet-up scripts (which add routes)
        // assume the iface is configured. Same loop shape as the
        // BecameReachable arm at gossip.rs:1061-1069.
        for s in &daemon.subnets.owned_by(&daemon.name) {
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
                    TimerWhat::KeyExpire => {
                        self.on_keyexpire();
                    }
                    TimerWhat::UdpPing => {
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
        for s in &self.subnets.owned_by(&self.name) {
            self.run_subnet_script(false, &self.name, s);
        }

        // C `net_setup.c:756-762` (`device_disable`): tinc-down
        // BEFORE device close. The script typically does `ip link
        // set down` / `ip addr del`. C calls it from `close_
        // network_connections` (`:1294`). `Drop` is the equivalent
        // teardown point; the device's own `Drop` runs after.
        // C `:1315` gates on `!device_standby`; we gate on whether
        // tinc-up actually fired (more correct — if standby and a
        // peer was reachable at shutdown, C's gate skips tinc-down
        // and relies on graph teardown to fire it; we don't run
        // graph in Drop, so check the actual state).
        if self.device_enabled {
            self.run_script("tinc-down");
        }
        let _ = std::fs::remove_file(&self.pidfile);
        // Signal handlers stay installed (SelfPipe::drop doesn't del
        // them — see tinc-event/sig.rs Drop doc). Process is exiting;
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

    /// `parse_bind_addr`: `"HOST [PORT]"`. Port optional, defaults
    /// to global. C `add_listen_address:639-649`.
    #[test]
    fn parse_bind_addr_cases() {
        // Both fields.
        assert_eq!(parse_bind_addr("10.0.0.1 5000", 655), ("10.0.0.1", 5000));
        // Port omitted → default.
        assert_eq!(parse_bind_addr("10.0.0.1", 655), ("10.0.0.1", 655));
        // Port 0 explicit (kernel picks).
        assert_eq!(parse_bind_addr("10.0.0.1 0", 655), ("10.0.0.1", 0));
        // Wildcard host. `*` handled by caller (build_listeners).
        assert_eq!(parse_bind_addr("* 5000", 655), ("*", 5000));
        // Unparseable port → default. C would feed it to getaddrinfo
        // (service-name resolution); we don't support that, fall back.
        assert_eq!(parse_bind_addr("10.0.0.1 http", 655), ("10.0.0.1", 655));
    }

    /// Construct a Config from `key = value` lines. Test-only.
    fn cfg_from(lines: &[&str]) -> tinc_conf::Config {
        let mut c = tinc_conf::Config::new();
        let entries: Vec<_> = lines
            .iter()
            .filter_map(|l| tinc_conf::parse_line(l, tinc_conf::Source::Cmdline { line: 0 }))
            .map(Result::unwrap)
            .collect();
        c.merge(entries);
        c
    }

    /// `build_listeners` no-config default = `open_listeners`.
    /// C `:1173`: `if(!cfgs) add_listen_address(NULL, NULL)`.
    #[test]
    fn build_listeners_no_config_is_wildcard() {
        let cfg = cfg_from(&[]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 1);
        assert!(ls[0].local.ip().is_unspecified());
        assert!(!ls[0].bindto, "wildcard default is bindto=false");
    }

    /// Two `BindToAddress` lines → two listener pairs. Port reuse:
    /// with `Port=0`, the second pair gets the first pair's port.
    /// C `net_setup.c:700`: `from_fd = listen_socket[0].tcp.fd`.
    #[test]
    fn build_listeners_two_bindto_shares_port() {
        // Two distinct loopback addrs. Linux routes the whole
        // 127.0.0.0/8 to lo; binding 127.42.x.x works without
        // setup. Avoid 127.0.0.x — the integration tests'
        // `alloc_port()` does bind-read-drop-rebind on 127.0.0.1
        // and we'd race for the same ephemeral.
        let cfg = cfg_from(&["BindToAddress = 127.42.0.1", "BindToAddress = 127.42.0.2"]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 2, "two BindToAddress → two pairs");
        assert!(ls[0].bindto && ls[1].bindto);
        assert_eq!(ls[0].local.ip().to_string(), "127.42.0.1");
        assert_eq!(ls[1].local.ip().to_string(), "127.42.0.2");

        let p = ls[0].local.port();
        assert_ne!(p, 0, "kernel assigned ephemeral");
        // The whole point of bind_reusing_port: every socket
        // converges on the first listener's port.
        assert_eq!(ls[0].udp_port(), p, "pair 0 UDP reused TCP");
        assert_eq!(ls[1].local.port(), p, "pair 1 TCP reused pair 0");
        assert_eq!(ls[1].udp_port(), p, "pair 1 UDP too");
    }

    /// `BindToAddress` vs `ListenAddress`: same plumbing, different
    /// `bindto` flag. C `:1160` (true) vs `:1169` (false).
    #[test]
    fn build_listeners_bindto_vs_listen() {
        let cfg = cfg_from(&["BindToAddress = 127.42.1.1", "ListenAddress = 127.42.1.2"]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 2);
        // BindToAddress walked first (C `:1156` before `:1164`).
        assert!(ls[0].bindto, "BindToAddress → bindto=true");
        assert!(!ls[1].bindto, "ListenAddress → bindto=false");
    }

    /// `BindToAddress = *` → wildcard. C `:649`: `"*"` → NULL host.
    #[test]
    fn build_listeners_wildcard_host() {
        let cfg = cfg_from(&["BindToAddress = *"]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 1);
        assert!(ls[0].local.ip().is_unspecified());
        // `*` via BindToAddress still gets bindto=true (vs the
        // no-config default which is false).
        assert!(ls[0].bindto);
    }

    /// Duplicate addresses skipped. C `:686-693` memcmp check.
    #[test]
    fn build_listeners_dedups() {
        let cfg = cfg_from(&[
            "BindToAddress = 127.42.2.1",
            "BindToAddress = 127.42.2.1", // duplicate
        ]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 1, "duplicate skipped");
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
        assert!(!s.strictsubnets); // C `:878` default false
        assert!(s.bind_to_address.is_none()); // C `:624` no default
        assert!(!s.directonly); // C `route.c:41`
        assert!(!s.priorityinheritance); // C `route.c:42`
        assert_eq!(s.forwarding_mode, ForwardingMode::Internal);
        // C `net_setup.c:561`: `else { autoconnect = true; }`.
        assert!(s.autoconnect);
        // C `protocol_misc.c:34-35`.
        assert_eq!(s.udp_info_interval, 5);
        assert_eq!(s.mtu_info_interval, 5);
        // C `net_setup.c:1257`: `maxoutbufsize = 10 * MTU`.
        assert_eq!(s.maxoutbufsize, 10 * MTU as usize);
        // C `net_socket.c:41-42`: `udp_{rcv,snd}buf = 1024*1024`.
        assert_eq!(s.sockopts.udp_rcvbuf, 1024 * 1024);
        assert_eq!(s.sockopts.udp_sndbuf, 1024 * 1024);
        assert_eq!(s.sockopts.fwmark, 0);
        // C `sptps.c:33`: `unsigned int sptps_replaywin = 32`.
        assert_eq!(s.replaywin, 32);
        // C `net_socket.c:45`: `int max_connection_burst = 10`.
        assert_eq!(s.max_connection_burst, 10);
        // C `net_packet.c:83`: `bool udp_discovery = true`.
        assert!(s.udp_discovery);
        // C `net_setup.c:57`: `bool device_standby = false`.
        assert!(!s.device_standby);
        assert!(s.scripts_interpreter.is_none());
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

    /// `net_setup.c:220-233` `get_name()` $-expansion + sanitize.
    #[test]
    fn expand_name_passthrough() {
        // No `$` prefix → returned as-is, NO sanitization. C only
        // sanitizes the env-expanded branch; literal Name goes
        // straight to check_id (which rejects `-`).
        assert_eq!(expand_name("node1").unwrap(), "node1");
        assert_eq!(expand_name("my-host").unwrap(), "my-host");
    }

    #[test]
    fn expand_name_envvar() {
        // `Name = $FOO` → getenv("FOO"). Non-alnum sanitized to `_`.
        // SAFETY: nextest runs each test in its own process by
        // default, so no concurrent env readers.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("TINC_TEST_NAME_PLAIN", "alpha42");
            std::env::set_var("TINC_TEST_NAME_DOTTED", "host.local");
            std::env::set_var("TINC_TEST_NAME_DASHED", "my-host");
        }
        assert_eq!(expand_name("$TINC_TEST_NAME_PLAIN").unwrap(), "alpha42");
        // C: `while(*c) if(!isalnum(*c)) *c='_';` — `.` → `_`.
        assert_eq!(expand_name("$TINC_TEST_NAME_DOTTED").unwrap(), "host_local");
        assert_eq!(expand_name("$TINC_TEST_NAME_DASHED").unwrap(), "my_host");
    }

    #[test]
    fn expand_name_unset_var_errors() {
        // C: `if(strcmp(name+1, "HOST")) { logger(ERR); return NULL; }`
        // Any unset var that isn't $HOST is fatal.
        let e = expand_name("$TINC_TEST_DEFINITELY_UNSET_XYZ").unwrap_err();
        assert!(e.contains("TINC_TEST_DEFINITELY_UNSET_XYZ"));
    }

    #[test]
    fn expand_name_host_fallback() {
        // `$HOST` falls back to gethostname() when unset. We can't
        // control the test machine's hostname, but we CAN assert:
        //   1. it succeeds
        //   2. result is non-empty
        //   3. result is fully alphanumeric (sanitized) — no `.`
        //      survived (C strips at first `.`, we sanitize it)
        // If $HOST happens to be set in env, that path is exercised
        // instead — same postconditions hold.
        let n = expand_name("$HOST").unwrap();
        assert!(!n.is_empty());
        assert!(n.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }
}
