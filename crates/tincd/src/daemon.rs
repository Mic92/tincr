//! `Daemon` — all the formerly-global state as one struct, plus the main loop.
//!
//! Loop shape: tick → turn → match. `IoWhat` is the `W` in
//! `EventLoop<W>`. `run()` consumes `self`; teardown is `Drop`.

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
use tinc_device::{Device, DeviceArena, GroBucket};
use tinc_event::{EventLoop, Io, IoId, Ready, SelfPipe, TimerId, Timers};
use tinc_graph::{EdgeId, Graph, NodeId, Route};
use tinc_proto::msg::{AddEdge, AnsKey, DelEdge, MtuInfo, ReqKey, SubnetMsg, UdpInfo};
use tinc_proto::{AddrStr, Request, Subnet};
use tinc_sptps::{Framing, Role, Sptps};

use crate::autoconnect::{self, AutoAction, NodeSnapshot};
use crate::conn::{Connection, FeedResult, SptpsEvent};
use crate::control::{ControlSocket, generate_cookie, write_pidfile};
#[cfg(not(target_os = "linux"))]
use crate::egress::Portable;
use crate::egress::{TxBatch, UdpEgress};
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
    /// broadcasts DEL_EDGE.
    pub edge: Option<EdgeId>,
    /// Direct connection. None = known but not directly connected.
    pub conn: Option<ConnId>,
    /// TCP addr, port rewritten to UDP.
    pub edge_addr: Option<SocketAddr>,
    /// Avg of RTTs, ms.
    pub edge_weight: i32,
    /// Top byte = peer's PROT_MINOR.
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

// DaemonSettings - the config knobs

/// Reloadable config knobs. Separate from `Daemon` so SIGHUP can
/// swap it wholesale. `Default` matches upstream tinc defaults.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // each bool is an
// independent config knob; grouping into state enums would obscure
// the 1:1 config-key mapping.
pub struct DaemonSettings {
    /// Seconds between pings. Default 60.
    pub pinginterval: u32,
    /// Seconds to wait for PONG before assuming peer dead. Clamped
    /// to `[1, pinginterval]`. Default 5.
    pub pingtimeout: u32,
    /// The `Port` config (HOST-tagged: from `hosts/NAME` not
    /// tinc.conf). Default 655. 0 means "kernel picks" - valid for
    /// tests; the actual port is read back from `listeners[0]`.
    pub port: u16,
    /// Filters which address families `open_listeners` tries.
    /// Default `Any` means dual-stack.
    pub addressfamily: AddrFamily,
    /// Retry-backoff cap in seconds. Default 900 (15 min).
    /// `retry_outgoing` caps `outgoing.timeout` here.
    pub maxtimeout: u32,
    /// Seconds. The laptop-suspend detector triggers if the ping
    /// timer didn't run for `> 2*this` seconds: the daemon was
    /// asleep, every peer has given up on us, force-close all conns
    /// to avoid sending into stale SPTPS contexts. Default 30.
    pub udp_discovery_timeout: u32,
    /// `Compression = N` config knob. Advertised in ANS_KEY; peers
    /// compress TOWARDS us at this level. Default 0 (none). 1-9
    /// zlib, 12 LZ4; 10-11 LZO (stubbed, rejected at setup).
    pub compression: u8,
    /// When set, `route_packet` decrements TTL after the forward
    /// decision. Makes `traceroute` through the mesh show each hop.
    /// Off by default because it MUTATES forwarded packets (TTL +
    /// IPv4 checksum); some payloads (e.g. ESP) hash the IP header.
    pub decrement_ttl: bool,
    /// Seconds between UDP probe-request sends when
    /// `!udp_confirmed`. Default 2.
    pub udp_discovery_interval: u32,
    /// Seconds between probe sends when `udp_confirmed`. Default 10.
    /// Keeps NAT mappings alive.
    pub udp_discovery_keepalive_interval: u32,
    /// Hub-mode: don't gossip indirect topology. Our direct peers
    /// learn each other only by us telling them; they can't learn
    /// each other's far-side neighbors. ADD/DEL_EDGE/SUBNET are
    /// filtered (drop if neither endpoint is us or a direct peer)
    /// and not forwarded.
    ///
    /// Implies `strictsubnets` (applied in `apply_reloadable_settings`
    /// after both are parsed): a hub doesn't gossip indirect topology
    /// AND doesn't trust direct peers to claim arbitrary subnets.
    pub tunnelserver: bool,
    /// The operator's `hosts/NAME` files become the AUTHORITY for
    /// which subnets each node owns. ADD_SUBNET gossip for subnets
    /// not in the file is ignored (forwarded, not added locally).
    /// DEL_SUBNET for subnets that ARE in the file is ignored.
    ///
    /// Implied by `tunnelserver`. `load_all_nodes` preloads the
    /// authorized subnets at startup; lookup-first means authorized
    /// gossip passes through silently (already-have-it noop).
    pub strictsubnets: bool,
    /// Route-time gate: if `owner != via` (would relay), send ICMP
    /// `NET_ANO` instead. The relay path EXISTS and works; this knob
    /// lets the operator say "don't use it".
    pub directonly: bool,
    /// Copy the inner packet's TOS/TC byte to the outer UDP socket
    /// via `IP_TOS`/`IPV6_TCLASS` before send. Without it, all
    /// encrypted traffic gets default DSCP regardless of inner QoS
    /// marking.
    pub priorityinheritance: bool,
    /// `Off` drops packets not addressed to us (leaf-only mode).
    /// `Kernel` writes everything from a peer straight to TUN, lets
    /// the OS routing table decide. Checked at the top of
    /// `route_packet`. Default `Internal`.
    pub forwarding_mode: ForwardingMode,
    /// Dispatch shape: `Router` → ethertype switch; `Switch` →
    /// `route_mac`; `Hub` → always broadcast. NOT reloadable -
    /// changing tun↔tap mid-run means re-opening the device.
    pub routing_mode: RoutingMode,
    /// The `RouteResult::Broadcast` arm dispatches on this. `None`
    /// drops all broadcasts; `Direct` only sends to one-hop
    /// neighbors (and only when WE originated). Default `Mst`.
    pub broadcast_mode: broadcast::BroadcastMode,
    /// Seconds. Lease TTL for learned MACs. The `age_subnets` 10s
    /// timer is the SWEEP frequency; this is the LEASE duration.
    /// Default 600.
    pub macexpire: u64,
    /// Bytes. Random Early Drop threshold for the meta-connection
    /// TCP outbuf - under load, RED keeps the buffer from growing
    /// unbounded by probabilistically dropping data packets queued
    /// behind a slow TCP send. Default `10 * MTU`.
    pub maxoutbufsize: usize,
    /// Config var `InvitationExpire`. `serve_cookie` checks
    /// `mtime + this < now`. Default one week.
    pub invitation_lifetime: Duration,
    /// When set, `try_udp` sends a SECOND probe to the peer's LAN-
    /// side address (from `ADD_EDGE.local_address`) when
    /// `!udp_confirmed`. Faster convergence when both nodes are on
    /// the same LAN behind the same NAT - the WAN probe round-trips
    /// through the NAT (or hairpin-fails); the LAN probe goes direct.
    pub local_discovery: bool,
    /// When set, outgoing meta-connections `bind()` to this local
    /// address before `connect()`. Useful for multi-homed hosts
    /// where the default route doesn't go via the desired interface.
    /// Config: `BindToAddress = HOST PORT` (port 0 = any).
    pub bind_to_address: Option<SocketAddr>,
    /// `None` = direct connect. `Exec` is socketpair+fork (no
    /// handshake); `Socks4`/`Socks5` connect to the proxy then send
    /// `socks::build_request` bytes before the ID line and read the
    /// fixed-length reply via `conn.tcplen`. `Http` sends
    /// `CONNECT host:port` then intercepts the line-based response
    /// in `metaconn.rs` before `check_gate` while `allow_request==Id`.
    pub proxy: Option<ProxyConfig>,
    /// Default **true**. When set, `periodic_handler` runs
    /// `do_autoconnect` every 5s: converge to ~3 direct connections.
    /// Tests that don't want surprise connections (most of them) set
    /// `AutoConnect = no`.
    pub autoconnect: bool,
    /// Seconds. Debounce for `send_udp_info` (only when WE
    /// originate). Default 5.
    pub udp_info_interval: u32,
    /// Seconds. Separate debounce from UDP_INFO. Default 5.
    pub mtu_info_interval: u32,
    /// Seconds. The KeyExpire timer fires at this interval and
    /// forces an SPTPS rekey on every tunnel with `validkey`.
    /// Default 3600.
    ///
    /// **Nonce-reuse guard.** SPTPS uses `outseqno: u32` as the
    /// ChaCha20-Poly1305 nonce; nothing checks for wraparound. At
    /// 1.5 Gbps / 1400-byte packets (≈134k pps), 2^32 packets is
    /// ≈9 hours to nonce reuse - catastrophic for ChaCha20-Poly1305.
    /// The 3600s timer caps any single key at ≈4.8e8 packets.
    pub keylifetime: u32,
    /// Per-listener sockopts. `UDPRcvBuf`/`UDPSndBuf`/`FWMark`/
    /// `BindToInterface` config keys. Non-reloadable: rebinding
    /// would mean closing all listeners. `fwmark` is also used by
    /// the outgoing-connect path (separate site, not yet wired).
    pub sockopts: SockOpts,
    /// `ScriptsInterpreter`. When `Some`, scripts are run as
    /// `<interp> <script>` instead of `<script>` directly. Unix
    /// shebang makes this redundant; useful for shebang-less hooks.
    pub scripts_interpreter: Option<String>,
    /// `ReplayWindow`. Datagram-mode anti-replay window size in
    /// packets. Passed to every `Sptps::start` for UDP tunnels.
    /// Default 32.
    pub replaywin: usize,
    /// `MaxConnectionBurst`. Tarpit leaky-bucket capacity. Same-host
    /// triggers at `> this`; all-host at `>= this`. Default 10.
    /// Non-reloadable: the tarpit is constructed once at setup.
    pub max_connection_burst: u32,
    /// `UDPDiscovery`. Master switch for the UDP probe machinery.
    /// Default true. When false, `try_udp` is a no-op and `try_mtu`
    /// skips the not-confirmed reset; the daemon falls back to
    /// TCP-only forwarding.
    pub udp_discovery: bool,
    /// Global `PMTU` from tinc.conf. Clamps ALL peers. Per-host
    /// `PMTU` also clamps (both apply, min wins).
    pub global_pmtu: Option<u16>,
    /// Global `Weight` from tinc.conf. Fallback when per-host
    /// `Weight` is absent. Overrides the RTT measurement.
    pub global_weight: Option<i32>,
    /// `DeviceStandby`. When set, `tinc-up` is NOT fired at setup:
    /// the script defers until the FIRST peer becomes reachable.
    /// Mirror for tinc-down: fired when the LAST peer becomes
    /// unreachable. For laptops that don't want a configured-but-
    /// unconnected tun0 hanging around. Non-reloadable.
    pub device_standby: bool,

    /// `DhtDiscovery` (Rust extension). BEP 42 port-probe for our public
    /// v4 + BEP 44 publish keyed by our Ed25519 pubkey. Off by default:
    /// publishing hands pubkey + candidate addrs to ~8 random DHT nodes
    /// in cleartext, and the keepalive holds a NAT hole open. For cold-
    /// start when you don't have one static `Address=`. Non-reloadable.
    pub dht_discovery: bool,

    /// `DhtBootstrap` (Rust extension). `host:port` seeds. Empty ⇒
    /// mainline's defaults. Replace, not augment: BEP 42 has no quorum
    /// threshold, so a single attacker-controlled bootstrap that wins
    /// the routing-table population race also fakes the port-probe echo
    /// (⇒ fakes the published `v4=`). NOT SAFE for invitations.
    pub dht_bootstrap: Vec<String>,
    // Chunk 4+: ~32 more fields.
}

/// Three-way forwarding knob. `Internal` gates the SPTPS_PACKET
/// relay; `Kernel` is checked at the top of `route_packet`:
/// anything from a peer goes straight to the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardingMode {
    /// Drop packets not addressed to us.
    Off,
    /// The daemon's `route()` does the forwarding decision.
    #[default]
    Internal,
    /// Write everything from a peer to TUN; let the OS routing
    /// table decide. Packets from OUR device still go through
    /// `route()` (we're the originator).
    Kernel,
}

/// Read once at setup, NOT reloadable (changing it mid-run would
/// mean re-opening the device tun→tap).
///
/// | Variant | Device | Dispatch |
/// |---|---|---|
/// | `Router` | TUN | `route()` ethertype switch |
/// | `Switch` | TAP | `route_mac()` |
/// | `Hub` | TAP | always `Broadcast` |
///
/// Hub mode broadcasts everything. No MAC learning, no subnet
/// table - pure flood. Niche; wired but untested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingMode {
    /// IP-layer routing.
    #[default]
    Router,
    /// MAC-layer routing with learning.
    Switch,
    /// Always broadcast. No learning.
    Hub,
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            pinginterval: 60,
            pingtimeout: 5,
            port: 655,
            addressfamily: AddrFamily::Any,
            maxtimeout: MAX_TIMEOUT_DEFAULT,
            udp_discovery_timeout: 30,
            compression: 0,
            decrement_ttl: false,
            udp_discovery_interval: 2,
            udp_discovery_keepalive_interval: 10,
            tunnelserver: false,
            strictsubnets: false,
            directonly: false,
            priorityinheritance: false,
            forwarding_mode: ForwardingMode::Internal,
            routing_mode: RoutingMode::Router,
            broadcast_mode: broadcast::BroadcastMode::Mst,
            macexpire: mac_lease::DEFAULT_EXPIRE_SECS,
            maxoutbufsize: 10 * MTU as usize,
            invitation_lifetime: Duration::from_secs(604_800), // 1 week
            local_discovery: true,
            bind_to_address: None,
            proxy: None,
            autoconnect: true,
            udp_info_interval: 5,
            mtu_info_interval: 5,
            keylifetime: 3600,
            sockopts: SockOpts::default(),
            scripts_interpreter: None,
            // 32 is strictly more tolerant of reordering than 16.
            replaywin: 32,
            max_connection_burst: 10,
            udp_discovery: true,
            global_pmtu: None,
            global_weight: None,
            device_standby: false,
            dht_discovery: false,
            dht_bootstrap: Vec::new(),
        }
    }
}

/// Parse the reloadable subset of settings from `config`. Called
/// from `setup()` AND `reload_configuration()`. Non-reloadable
/// settings (Port, AddressFamily, DeviceType) are NOT here - they
/// need re-bind / re-open which `setup()` does inline.
#[allow(clippy::too_many_lines)] // flat config→settings field map; one key per block, no branching
fn apply_reloadable_settings(config: &tinc_conf::Config, settings: &mut DaemonSettings) {
    if let Some(e) = config.lookup("PingInterval").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.pinginterval = v;
    }
    // Clamped to [1, pinginterval].
    if let Some(e) = config.lookup("PingTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.pingtimeout = v.clamp(1, settings.pinginterval);
    }
    // Per-host PMTU is read in proto.rs::handle_id; this is the
    // tinc.conf-level clamp.
    if let Some(e) = config.lookup("PMTU").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u16::try_from(v)
    {
        settings.global_pmtu = Some(v);
    }
    // Fallback when per-host Weight absent.
    if let Some(e) = config.lookup("Weight").next()
        && let Ok(v) = e.get_int()
    {
        settings.global_weight = Some(v);
    }
    if let Some(e) = config.lookup("MaxTimeout").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.maxtimeout = v;
    }
    if let Some(e) = config.lookup("DecrementTTL").next()
        && let Ok(v) = e.get_bool()
    {
        settings.decrement_ttl = v;
    }
    if let Some(e) = config.lookup("TunnelServer").next()
        && let Ok(v) = e.get_bool()
    {
        settings.tunnelserver = v;
    }
    if let Some(e) = config.lookup("StrictSubnets").next()
        && let Ok(v) = e.get_bool()
    {
        settings.strictsubnets = v;
    }
    // tunnelserver implies strictsubnets. Applied after BOTH parsed.
    settings.strictsubnets |= settings.tunnelserver;
    if let Some(e) = config.lookup("LocalDiscovery").next()
        && let Ok(v) = e.get_bool()
    {
        settings.local_discovery = v;
    }
    if let Some(e) = config.lookup("DirectOnly").next()
        && let Ok(v) = e.get_bool()
    {
        settings.directonly = v;
    }
    if let Some(e) = config.lookup("PriorityInheritance").next()
        && let Ok(v) = e.get_bool()
    {
        settings.priorityinheritance = v;
    }
    if let Some(e) = config.lookup("AutoConnect").next()
        && let Ok(v) = e.get_bool()
    {
        settings.autoconnect = v;
    }
    // No sandbox gate here: at Sandbox=normal Landlock grants
    // Execute on confbase so an interpreter under confbase works;
    // /usr/bin/python won't, but that's true on first boot too, not
    // just on reload. At Sandbox=high, scripts don't run at all so
    // this is moot. ScriptsExtension is NOT parsed (Windows-only).
    settings.scripts_interpreter = config
        .lookup("ScriptsInterpreter")
        .next()
        .map(|e| e.get_str().to_owned());
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
    // Silently keep default on <=0 (less harsh on reload typo).
    if let Some(e) = config.lookup("MaxConnectionBurst").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
        && v >= 1
    {
        settings.max_connection_burst = v;
    }
    if let Some(e) = config.lookup("ReplayWindow").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = usize::try_from(v)
    {
        settings.replaywin = v;
    }
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
    // Log + keep default on unknown (less harsh on reload typo).
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
    if let Some(e) = config.lookup("MACExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u64::try_from(v)
    {
        settings.macexpire = v;
    }
    if let Some(e) = config.lookup("MaxOutputBufferSize").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = usize::try_from(v)
    {
        settings.maxoutbufsize = v;
    }
    if let Some(e) = config.lookup("InvitationExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u64::try_from(v)
    {
        settings.invitation_lifetime = Duration::from_secs(v);
    }
    if let Some(e) = config.lookup("KeyExpire").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.keylifetime = v;
    }
}

/// Parse `Subnet =` lines for `myname` from `config`. Factored from
/// `setup()` so `reload_configuration()` can call the same parser.
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

/// Parse `ConnectTo =` names from `config`. Filters invalid names
/// and self-reference.
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
/// Split on first space; port half is optional (defaults to global
/// `Port`). `"*"` means the wildcard - `build_listeners` translates
/// it to the literal wildcard IP per requested family.
fn parse_bind_addr(s: &str, default_port: u16) -> (&str, u16) {
    let mut parts = s.splitn(2, ' ');
    let host = parts.next().unwrap_or("");
    // Numeric only (no service-name resolution).
    let port = parts
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    (host, port)
}

/// For each `BindToAddress` line then each `ListenAddress` line,
/// resolve and create listener pair(s). If neither key is present,
/// fall through to the wildcard default (`open_listeners`).
///
/// Port reuse: the first listener picks an ephemeral with `Port=0`;
/// every subsequent bind tries to reuse it so the daemon advertises
/// ONE port to peers regardless of how many addresses it listens on.
///
/// `bindto`: `BindToAddress` listeners are also used as outgoing-
/// connect source addresses; `ListenAddress` listeners are listen-only.
fn build_listeners(
    config: &tinc_conf::Config,
    port: u16,
    family: AddrFamily,
    opts: &SockOpts,
) -> Vec<Listener> {
    let mut listeners: Vec<Listener> = Vec::new();
    // None until the first successful bind.
    let mut reuse_port: Option<u16> = if port == 0 { None } else { Some(port) };
    let mut cfgs = 0usize;
    // Dedup tracks the REQUESTED (pre-bind) addrs, not `l.local`
    // (that's post-bind with ephemeral filled in).
    let mut requested: Vec<SocketAddr> = Vec::new();

    let mut try_addr = |addr: SocketAddr, bindto: bool| {
        if requested.contains(&addr) {
            return;
        }
        requested.push(addr);
        if listeners.len() >= MAXSOCKETS {
            log::error!(target: "tincd::net", "Too many listening sockets");
            return;
        }
        if let Some(l) = open_listener_pair(addr, opts, reuse_port, bindto) {
            // First successful bind seeds the reuse port (only
            // meaningful when Port=0).
            if reuse_port.is_none() {
                reuse_port = Some(l.local.port());
            }
            listeners.push(l);
        }
    };

    for (key, bindto) in [("BindToAddress", true), ("ListenAddress", false)] {
        for e in config.lookup(key) {
            cfgs += 1;
            let s = e.get_str();
            let (host, p) = parse_bind_addr(s, port);
            // Synthesize wildcard addrs directly; skips the resolver.
            if host == "*" {
                if family.try_v4() {
                    try_addr((std::net::Ipv4Addr::UNSPECIFIED, p).into(), bindto);
                }
                if family.try_v6() {
                    try_addr((std::net::Ipv6Addr::UNSPECIFIED, p).into(), bindto);
                }
                continue;
            }
            // A hostname may resolve to multiple addrs (v4+v6); bind
            // each. to_socket_addrs doesn't take a family hint, so
            // filter post-resolve.
            match (host, p).to_socket_addrs() {
                Ok(iter) => {
                    for addr in iter {
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
                    // Lenient: skip this entry, try the rest. If ALL
                    // fail, the empty-listeners check below catches it.
                    log::error!(target: "tincd::net",
                                "{key} = {s}: {e}");
                }
            }
        }
    }

    // No config → wildcard default.
    if cfgs == 0 {
        return open_listeners(port, family, opts);
    }

    listeners
}

/// `Name = $FOO` reads env var `FOO`. `Name = $HOST` falls back to
/// `gethostname(2)` truncated at the first `.` when the env var is
/// unset. The result is sanitized: any non-alnum char becomes `_`,
/// so a hostname like `my-host` is a valid node name.
///
/// Names without a `$` prefix are returned unchanged (NOT sanitized;
/// only the env branch is sanitized).
#[allow(unsafe_code)] // libc::gethostname; nix `hostname` feature not enabled
fn expand_name(name: &str) -> Result<String, String> {
    let Some(var) = name.strip_prefix('$') else {
        return Ok(name.to_owned());
    };

    let raw = match std::env::var(var) {
        Ok(v) => v,
        Err(_) if var == "HOST" => {
            let mut buf = [0u8; 32];
            // SAFETY: buf is valid, len is correct. POSIX leaves
            // gethostname truncation unspecified - force-NUL the
            // last byte.
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
            // Strip domain part.
            let dot = buf[..nul].iter().position(|&b| b == b'.').unwrap_or(nul);
            String::from_utf8_lossy(&buf[..dot]).into_owned()
        }
        Err(_) => {
            return Err(format!(
                "Invalid Name: environment variable {var} does not exist"
            ));
        }
    };

    Ok(raw
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect())
}

/// Parse the non-reloadable settings from `config` into a fresh
/// `DaemonSettings`. Called once from `setup()`. Reloadable settings
/// are folded in via `apply_reloadable_settings`; the rest (Port,
/// AddressFamily, Mode, sockopts, Proxy, Compression, Forwarding,
/// DHT, DeviceStandby) need re-bind / re-open and are setup-only.
#[allow(clippy::too_many_lines)] // flat config→settings field map; one key per block, no branching
fn load_settings(config: &tinc_conf::Config) -> Result<DaemonSettings, SetupError> {
    let mut settings = DaemonSettings::default();

    // Port. HOST-tagged. `Port = 0` is valid: kernel picks (tests
    // use this). Non-numeric Port (service-name resolution) not
    // supported; reject.
    if let Some(e) = config.lookup("Port").next() {
        settings.port = e.get_str().parse().map_err(|_| {
            SetupError::Config(format!("Port = {} is not a valid port number", e.get_str()))
        })?;
    }

    // AddressFamily. SERVER-tagged. Unknown values silently
    // ignored; stays at default.
    if let Some(e) = config.lookup("AddressFamily").next() {
        if let Some(af) = AddrFamily::from_config(e.get_str()) {
            settings.addressfamily = af;
        } else {
            log::warn!(target: "tincd",
                       "Unknown AddressFamily = {}, using default",
                       e.get_str());
        }
    }

    // Reloadable settings. Factored into a helper so
    // reload_configuration can call it too.
    // NOT Port/AddressFamily (those need re-bind, setup-only).
    apply_reloadable_settings(config, &mut settings);

    // BindToAddress for outgoing source-addr selection. Non-
    // reloadable. We only stash the FIRST entry here for the
    // outgoing-connect bind; the FULL set is re-read below in the
    // listener-creation block.
    if let Some(e) = config.lookup("BindToAddress").next() {
        let s = e.get_str();
        let (host, port) = parse_bind_addr(s, 0);
        match (host, port).to_socket_addrs() {
            Ok(mut iter) => settings.bind_to_address = iter.next(),
            Err(e) => {
                log::warn!(target: "tincd",
                           "BindToAddress = {s}: {e}; not binding");
            }
        }
    }

    // UDPRcvBuf / UDPSndBuf. Warnings enabled ONLY when the
    // operator explicitly configures - the 1MB default tripping
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

    // FWMark. 0 (default/unset) means "skip".
    if let Some(e) = config.lookup("FWMark").next()
        && let Ok(v) = e.get_int()
        && let Ok(v) = u32::try_from(v)
    {
        settings.sockopts.fwmark = v;
    }

    // BindToInterface. Hoisted to setup-time; not reloadable
    // (sockets are already bound).
    if let Some(e) = config.lookup("BindToInterface").next() {
        settings.sockopts.bind_to_interface = Some(e.get_str().to_owned());
    }

    // Proxy. Non-reloadable: our outgoing-connection path reads
    // it at dial time; reload would need to re-dial existing conns.
    if let Some(e) = config.lookup("Proxy").next() {
        settings.proxy = parse_proxy_config(e.get_str()).map_err(SetupError::Config)?;
    }

    // Compression. HOST-tagged. The level WE want peers to
    // compress towards us at. Reject LZO (stubbed) and >12.
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

    // Mode. NOT in apply_reloadable_settings (device re-open).
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

    // DeviceStandby. Non-reloadable: decides whether tinc-up
    // fires at setup vs first-peer.
    if let Some(e) = config.lookup("DeviceStandby").next()
        && let Ok(v) = e.get_bool()
    {
        settings.device_standby = v;
    }

    // Rust extension. Non-reloadable.
    if let Some(e) = config.lookup("DhtDiscovery").next()
        && let Ok(v) = e.get_bool()
    {
        settings.dht_discovery = v;
    }
    settings.dht_bootstrap = config
        .lookup("DhtBootstrap")
        .map(|e| e.get_str().to_owned())
        .collect();

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

    Ok(settings)
}

/// Open the tun/tap/fd device per `DeviceType`. Factored from
/// `setup()`: pure config→Device, no daemon state.
fn open_device(config: &tinc_conf::Config) -> Result<Box<dyn Device>, SetupError> {
    let device_type = config
        .lookup("DeviceType")
        .next()
        .map(|e| e.get_str().to_ascii_lowercase());
    let device: Box<dyn Device> = match device_type.as_deref() {
        None | Some("dummy") => Box::new(tinc_device::Dummy),
        #[cfg(target_os = "linux")]
        Some("fd") => {
            // The fd comes from `Device = N` (inherited fd) or
            // `--device-fd N`. The integration test creates a
            // socketpair, writes one end's fd into `Device = N`,
            // and pumps IP packets through it. `FdTun` reads at
            // `+14` (raw IP, no tun_pi prefix) and synthesizes
            // the ethertype - the framing `route()` expects.
            let dev_str = config
                .lookup("Device")
                .next()
                .map(tinc_conf::Entry::get_str)
                .ok_or_else(|| SetupError::Config("DeviceType=fd requires Device = <fd>".into()))?;
            let fd: std::os::unix::io::RawFd = dev_str
                .parse()
                .map_err(|_| SetupError::Config(format!("Device = {dev_str} is not a valid fd")))?;
            let tun = tinc_device::FdTun::open(tinc_device::FdSource::Inherited(fd))
                .map_err(SetupError::Io)?;
            Box::new(tun)
        }
        #[cfg(target_os = "linux")]
        Some("tun") => {
            // Real kernel TUN via `/dev/net/tun` + TUNSETIFF.
            // Needs `CAP_NET_ADMIN`; the netns harness grants it
            // inside an unprivileged userns via bwrap.
            //
            // `Interface = NAME` → attach to a precreated
            // persistent device; unset → kernel picks `tun0`/etc.
            // The netns test precreates so it can move the device
            // into a child netns AFTER the daemon attaches (the
            // fd→device binding survives `ip link set netns`).
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
            // TODO: auto-derive tap when Mode != router and
            // DeviceType is unset. We only handle the explicit
            // form here; the cross-impl test sets it explicitly.
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
    Ok(device)
}

/// Register each listener pair on the event loop and wrap into
/// `ListenerSlot`s. Factored from `setup()`: consumes the bare
/// `Listener`s and yields the daemon-side slots.
fn register_listeners(
    listeners: Vec<Listener>,
    ev: &mut EventLoop<IoWhat>,
) -> Result<Vec<ListenerSlot>, SetupError> {
    let mut listener_slots = Vec::with_capacity(listeners.len());
    for (i, l) in listeners.into_iter().enumerate() {
        let (tcp_fd, udp_fd) = l.fds();
        #[allow(clippy::cast_possible_truncation)] // MAXSOCKETS=8 fits in u8
        let i = i as u8;
        ev.add(tcp_fd, Io::Read, IoWhat::Tcp(i))
            .map_err(SetupError::Io)?;
        let udp_io = ev
            .add(udp_fd, Io::Read, IoWhat::Udp(i))
            .map_err(SetupError::Io)?;
        // Phase 1 (`RUST_REWRITE_10G.md`): on Linux, dup into
        // `linux::Fast` (UDP_SEGMENT cmsg, one sendmsg per
        // batch). No probe: kernel ≥4.18 floor; ENOPROTOOPT at
        // first batch → panic with a clear message (see
        // `egress/linux.rs::map_errno`). Non-Linux stays
        // `Portable` (count × sendto).
        //
        // The listener keeps its copy for `recvmmsg`; the egress
        // sends on the dup. Same file description → same bound
        // addr, same TOS (the daemon's `set_udp_tos` sets it on
        // the listener fd).
        #[cfg(target_os = "linux")]
        let egress: Box<dyn UdpEgress> =
            Box::new(crate::egress::linux::Fast::new(&l.udp).map_err(SetupError::Io)?);
        #[cfg(not(target_os = "linux"))]
        let egress: Box<dyn UdpEgress> = Box::new(Portable::new(&l.udp).map_err(SetupError::Io)?);
        listener_slots.push(ListenerSlot {
            listener: l,
            udp_io,
            last_tos: 0,
            egress,
        });
    }
    Ok(listener_slots)
}

/// Parse `DNSAddress`/`DNSSuffix` into `DnsConfig`. Rust-only
/// extension. Off (returns `Ok(None)`) unless BOTH are set.
fn load_dns_config(
    config: &tinc_conf::Config,
) -> Result<Option<crate::dns::DnsConfig>, SetupError> {
    let mut a4 = None;
    let mut a6 = None;
    for e in config.lookup("DNSAddress") {
        match e.get_str().parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v)) => a4 = Some(v),
            Ok(std::net::IpAddr::V6(v)) => a6 = Some(v),
            Err(_) => {
                return Err(SetupError::Config(format!(
                    "DNSAddress = {}: not a valid IP address",
                    e.get_str()
                )));
            }
        }
    }
    let suffix = config
        .lookup("DNSSuffix")
        .next()
        .map(|e| e.get_str().trim_matches('.').to_owned());
    match (a4.is_some() || a6.is_some(), suffix) {
        (true, Some(suffix)) => {
            log::info!(target: "tincd::dns",
                       "DNS stub enabled: {} for *.{suffix}",
                       a4.map(|a| a.to_string())
                         .into_iter()
                         .chain(a6.map(|a| a.to_string()))
                         .collect::<Vec<_>>()
                         .join(" + "));
            Ok(Some(crate::dns::DnsConfig {
                dns_addr4: a4,
                dns_addr6: a6,
                suffix,
            }))
        }
        (true, None) => Err(SetupError::Config(
            "DNSAddress set but DNSSuffix missing".into(),
        )),
        (false, Some(_)) => Err(SetupError::Config(
            "DNSSuffix set but DNSAddress missing".into(),
        )),
        (false, None) => Ok(None),
    }
}

// Daemon — the formerly-global state + the loop

/// What `run()` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// Loop returned cleanly (`running` set false by a handler).
    Clean,
    /// Poll returned an error.
    PollError,
}

/// Daemon-side wrapper around `Listener`. Bundles the event-loop
/// `IoId` (for UDP rearm after a `recvmmsg` batch cap; bug audit
/// `deef1268`) and the last `IP_TOS`/`IPV6_TCLASS` set on the UDP
/// socket (only `setsockopt` when changed). Kept here, not on
/// `Listener`, so `listen.rs` stays event-loop-agnostic.
pub(crate) struct ListenerSlot {
    pub(crate) listener: Listener,
    pub(crate) udp_io: IoId,
    pub(crate) last_tos: u8,
    /// `UdpEgress` for this listener's UDP socket. Phase 0
    /// (`RUST_REWRITE_10G.md`): always `Portable` (count × sendto,
    /// same wire output as the direct `udp.send_to` it replaced).
    /// Phase 1 swaps `linux::Fast` (UDP_SEGMENT cmsg) on Linux.
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
    pub(crate) conn_io: slotmap::SecondaryMap<ConnId, IoId>,

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

    /// Our options bitfield (PROT_MINOR in top byte). Built from
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
    /// added by `lookup_or_add_node` from ADD_EDGE/ADD_SUBNET
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

    /// The routing table. ADD_SUBNET inserts, DEL_SUBNET removes,
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
    /// ADD_EDGE) are graph-only.
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
    /// Same, for DEL_EDGE: peer says we DON'T have an edge we DO have.
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

    /// Per-daemon compression workspace. Currently a ZST (lz4_flex
    /// is stateless, zlib one-shot per call); kept as a struct so
    /// adding persistent z_stream state doesn't churn wire-up sites.
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

    /// GRO TUN-write coalescer (`RUST_REWRITE_10G.md` Phase 2b).
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

    /// The device fd's `IoId`. `None` for `Dummy` (no fd, never
    /// registered). Stored so `on_device_read` can `rearm()` after
    /// hitting its drain-loop iteration cap - see the bounded-drain
    /// comment in that fn for why this matters under sustained load.
    pub(crate) device_io: Option<IoId>,

    /// Slot arena for `Device::drain` (`RUST_REWRITE_10G.md` Phase
    /// 0). Replaces `on_device_read`'s 1.5KB stack buf: drain reads
    /// frames into slots, the loop body walks them. Phase 1 widens:
    /// encrypt into slots, hand the contiguous run to `egress`.
    /// Phase 0 only uses it on the read side; `tx_scratch` stays
    /// for the encrypt path until Phase 1 unifies them (separate
    /// buffers, no overlap).
    ///
    /// `Option` for the same `mem::take` dance as `udp_rx_batch`:
    /// `route_packet` borrows `&mut self`; the arena slot borrow
    /// conflicts. Take, walk, put back.
    pub(crate) device_arena: Option<DeviceArena>,

    /// `tso_split` output scratch (`RUST_REWRITE_10G.md` Phase 2a).
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

    /// TX batch accumulator (`RUST_REWRITE_10G.md` Phase 1). The
    /// `on_device_read` drain loop stages encrypted frames here
    /// instead of `sendto`-per-frame; one `EgressBatch` ships the
    /// run after the loop. `None` outside the drain loop - the send
    /// site (`send_sptps_data_relay`) checks: `Some` ⇒ stage,
    /// `None` ⇒ immediate send (the Phase-0 path; still hit by
    /// UDP-recv → forward, meta-conn → relay, probe sends).
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
    /// `mac_table` (via gossip ADD_SUBNET) but not here. Lifecycles
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
    /// `mio::Poll` + slot table. Generic over `IoWhat`.
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
    /// exist) - the `?` greeting is then rejected at id_h.
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
    /// monotonic-node usage). Helper consolidates 11 callsites that
    /// previously open-coded the `map_or`.
    pub(super) fn node_log_name(&self, nid: NodeId) -> &str {
        self.graph.node(nid).map_or("<gone>", |n| n.name.as_str())
    }

    /// `confbase` is the `-c` argument (or `CONFDIR/tinc[/NETNAME]`
    /// resolved by main.rs). `pidfile`/`socket` are the runtime paths.
    ///
    /// # Errors
    /// Startup failures: tinc.conf missing/malformed, no `Name`,
    /// device open failed, pidfile write failed (permissions),
    /// socket bind failed (already running).
    ///
    /// # Panics
    /// `SelfPipe::new` panics if a SelfPipe already exists in this
    /// process (it's a singleton - see tinc-event/sig.rs). Can't
    /// happen here: setup is called once. Tests that call setup
    /// twice in one process are wrong; integration tests use
    /// subprocess.
    #[allow(clippy::too_many_lines)] // boot wiring + ~100-line struct literal; phases extracted, rest is glue
    pub fn setup(
        confbase: &Path,
        pidfile: &Path,
        socket: &Path,
        cmdline_conf: &tinc_conf::Config,
        socket_activation: Option<usize>,
    ) -> Result<Self, SetupError> {
        // ─── read tinc.conf
        let mut config = tinc_conf::read_server_config(confbase)
            .map_err(|e| SetupError::Config(format!("{e}")))?;

        // ─── cmdline -o overrides
        // Merge order doesn't matter: Source::Cmdline sorts before
        // Source::File regardless. Empty cmdline_conf is a no-op.
        config.merge(cmdline_conf.entries().iter().cloned());

        // ─── Name
        // TODO: validate with check_id (alphanumeric + `_`). Currently
        // only the ConnectTo path uses it; Name itself is unvalidated.
        let name = config
            .lookup("Name")
            .next()
            .map(tinc_conf::Entry::get_str)
            .ok_or(SetupError::Config("Name for tinc daemon required!".into()))?;
        let name = expand_name(name).map_err(SetupError::Config)?;
        log::info!(target: "tincd", "tincd starting, name={name}");

        // ─── read host config
        // Merge hosts/NAME into the same tree as tinc.conf. HOST-tagged
        // vars (Port, Subnet, PublicKey, etc) live there. Missing
        // hosts/NAME is not fatal: the only var we read from it here
        // is Port, which has a default. Hard failures (no key, no
        // subnets) come later.
        let host_file = confbase.join("hosts").join(&name);
        match tinc_conf::parse_file(&host_file) {
            Ok(entries) => config.merge(entries),
            Err(e) => {
                // Warn-level: MIGHT be intentional (freshly-init'd
                // daemon has no hosts/ yet) but more likely a Name typo.
                log::warn!(target: "tincd",
                           "hosts/{name} not read: {e}; using defaults");
            }
        }

        // ─── private key
        // Missing key is FATAL: we forbid legacy, so there is no RSA
        // fallback. The error message includes the gen-keys hint so
        // the user knows what to do.
        let mykey = read_ecdsa_private_key(&config, confbase).map_err(|e| {
            let hint = if matches!(e, PrivKeyError::Missing(_)) {
                "\n  (Create a key pair with `tinc generate-ed25519-keys`)"
            } else {
                ""
            };
            SetupError::Config(format!("{e}{hint}"))
        })?;

        // ─── settings
        let settings = load_settings(&config)?;

        // ─── device
        let device = open_device(&config)?;
        // Captured BEFORE the Box goes into the Daemon struct: the
        // `&dyn` trait borrow makes `&mut self` script call sites
        // awkward.
        let iface = device.iface().to_owned();
        let device_mode = device.mode();
        log::info!(target: "tincd",
                   "Device mode: {device_mode:?}, interface: {iface}");

        // TAP-ish device + Mode=router → kernel emits/expects eth
        // frames but our routing layer ignores MACs. The stamp writes
        // a valid dst-MAC on the way to the device.
        let overwrite_mac =
            device_mode == tinc_device::Mode::Tap && settings.routing_mode == RoutingMode::Router;
        // Locally-administered placeholder; SIOCGIFHWADDR seeds from
        // the kernel, the ARP/NDP snatch then keeps it fresh.
        let mymac = device.mac().unwrap_or([0xFE, 0xFD, 0, 0, 0, 0]);

        // ─── event loop scaffolding
        // tinc-event constructors. EventLoop::new can fail (epoll_
        // create); the others can't (BTreeMap, pipe).
        let mut ev = EventLoop::new().map_err(SetupError::Io)?;
        let mut timers = Timers::new();
        let mut signals = SelfPipe::new().map_err(SetupError::Io)?;

        // ─── signals
        // TERM/QUIT/INT all map to Exit. HUP → Reload, ALRM → Retry.
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

        // Register the self-pipe read end.
        ev.add(signals.read_fd(), Io::Read, IoWhat::Signal)
            .map_err(SetupError::Io)?;

        // ─── device fd
        // Dummy returns None; Tun/Fd/Raw/Bsd return Some(fd).
        let device_io = if let Some(fd) = device.fd() {
            Some(
                ev.add(fd, Io::Read, IoWhat::Device)
                    .map_err(SetupError::Io)?,
            )
        } else {
            None
        };

        // ─── ping timer
        // Initial fire is `pingtimeout` seconds from now; the handler
        // re-arms at +1s. tinc-event re-arm is EXPLICIT - the match
        // arm calls `timers.set(pingtimer, ...)`.
        let pingtimer = timers.add(TimerWhat::Ping);
        timers.set(
            pingtimer,
            Duration::from_secs(u64::from(settings.pingtimeout)),
        );

        // ─── age_past_requests timer
        // Re-arms +10s. The eviction window is `pinginterval` (the
        // cache key TTL); the timer's 10s is just the sweep frequency.
        let age_timer = timers.add(TimerWhat::AgePastRequests);
        timers.set(age_timer, Duration::from_secs(10));

        // ─── periodic timer
        // Arm +5s directly: no contradictions exist at setup, counters
        // are zero, an immediate first call would just halve sleeptime
        // (10 → 5 → floored to 10) and re-arm.
        let periodictimer = timers.add(TimerWhat::Periodic);
        timers.set(periodictimer, Duration::from_secs(5));

        // ─── keyexpire timer
        // Arm unconditionally: SPTPS needs the rekey to bound the
        // ChaCha20 nonce counter (see `keylifetime` doc).
        let keyexpire_timer = timers.add(TimerWhat::KeyExpire);
        timers.set(
            keyexpire_timer,
            Duration::from_secs(u64::from(settings.keylifetime)),
        );

        // ─── listeners
        // Socket activation BYPASSES BindToAddress/ListenAddress
        // entirely (the .socket unit IS the bind config). Otherwise
        // walk BindToAddress, then ListenAddress, else wildcard.
        // Empty result is a hard error: the daemon can't function
        // without at least one listener.
        let listeners = if let Some(n) = socket_activation {
            crate::listen::adopt_listeners(n, &settings.sockopts)
                .map_err(|e| SetupError::Config(format!("socket activation: {e}")))?
        } else {
            build_listeners(
                &config,
                settings.port,
                settings.addressfamily,
                &settings.sockopts,
            )
        };
        // Always read back the bound port - same answer when port≠0
        // (kernel binds the requested port). `first()` not `[0]`:
        // the empty-check below still wants its own error message.
        let my_udp_port = listeners.first().map_or(0, Listener::udp_port);
        if listeners.is_empty() {
            return Err(SetupError::Config(
                "Unable to create any listening socket!".into(),
            ));
        }
        // Map listeners[0]'s bound addr 0.0.0.0→127.0.0.1, format
        // `"HOST port PORT"`. Pidfile format is fixed (the CLI on
        // Windows actually connects to this addr; Unix uses the unix
        // socket and ignores it). Computed before `listeners` is
        // consumed into `ListenerSlot`s.
        let address = pidfile_addr(&listeners);
        // Register each pair. Index `i` becomes `IoWhat::Tcp(i)` so
        // the dispatch arm can index back for the accept.
        let listener_slots = register_listeners(listeners, &mut ev)?;

        // ─── init_control
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

        // ─── graph: add myself
        // `Graph::add_node` defaults `reachable = true`.
        let mut graph = Graph::new();
        let myself = graph.add_node(&name);
        let mut node_ids = HashMap::new();
        node_ids.insert(name.clone(), myself);
        let mut id6_table = NodeId6Table::new();
        id6_table.add(&name, myself);

        // ─── Subnet
        // OUR subnets from `hosts/NAME` (HOST-tagged). `route()`
        // needs these to recognize packets destined for us. Parse
        // failures are logged + skipped (the bad subnet just isn't
        // routable).
        let mut subnets = SubnetTree::new();
        for s in parse_subnets_from_config(&config, &name) {
            subnets.add(s, name.clone());
        }

        // ─── DNS stub (Rust-only)
        // Tailscale-style TUN intercept. Off unless BOTH
        // `DNSAddress=` and `DNSSuffix=` are set. The magic IP must
        // also be added to the TUN in `tinc-up`. `DNSAddress` can be
        // repeated for v4+v6.
        let dns = load_dns_config(&config)?;

        // ─── BroadcastSubnet
        // Hard-coded multicast/broadcast subnets, ownerless →
        // `route_broadcast`. Without these, kernel multicast (mDNS,
        // NDP, DHCP) read from TUN hit Unreachable and we ICMP-bounce
        // our own kernel. Silent breakage - mDNS doesn't surface
        // ICMP. (`Mode = switch` unaffected: route_mac floods on
        // miss anyway.)
        for s in [
            "ff:ff:ff:ff:ff:ff",
            "255.255.255.255",
            "224.0.0.0/4",
            "ff00::/8",
        ] {
            subnets.add_broadcast(s.parse().expect("hard-coded broadcast subnet"));
        }
        for e in config.lookup("BroadcastSubnet") {
            match e.get_str().parse::<Subnet>() {
                Ok(s) => subnets.add_broadcast(s),
                Err(_) => {
                    log::error!(target: "tincd",
                                "Invalid BroadcastSubnet = {}", e.get_str());
                }
            }
        }

        // ─── ConnectTo
        // Collect names here; the actual connect is done below (it
        // needs `&mut self`). The mark-sweep (terminate connections
        // whose ConnectTo was removed) only matters on SIGHUP-reload.
        let connect_to = parse_connect_to_from_config(&config, &name);

        // ─── invitation key
        // `Ok(None)` if the file doesn't exist - not an error, just
        // no invites issued yet. `Err` for corrupt PEM.
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
            // Seed with now: a zero seed would tarpit the first burst
            // window from epoch.
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
            gro_bucket: None,
            gro_bucket_spare: Some(GroBucket::new()),
            // Linux TUN: vnet_hdr is unconditional since `5cf9b12d`.
            // TAP/FdTun/BSD/Dummy: trait default returns Unsupported.
            // Gate here so we never `offer()` into a bucket whose
            // flush will fail at write - that would silently drop
            // every coalesced burst.
            #[cfg(target_os = "linux")]
            gro_enabled: device_mode == tinc_device::Mode::Tun,
            #[cfg(not(target_os = "linux"))]
            gro_enabled: false,
            // Seed with now: the first `on_ping_tick` (after
            // `pingtimeout` seconds) sees a delta of `pingtimeout`,
            // well under the `2*30` suspend-detect threshold.
            last_periodic_run_time: timers.now(),
            iface,
            overwrite_mac,
            mymac,
            device_errors: 0,
            device_io,
            device_arena: Some(DeviceArena::new(net::DEVICE_DRAIN_CAP)),
            // Lazy: only allocated on first `DrainResult::Super`.
            // TAP and non-Linux backends never produce Super,
            // never spend the 100KB.
            tso_scratch: None,
            tso_lens: vec![0usize; net::DEVICE_DRAIN_CAP].into_boxed_slice(),
            // None: the send site only stages when inside
            // `on_device_read`'s drain loop. The TxBatch itself
            // is built lazily on first drain (no point allocating
            // ~100KB on a tunnelserver that never sees device reads).
            tx_batch: None,
            outgoings: SlotMap::with_key(),
            outgoing_timers: slotmap::SecondaryMap::new(),
            connecting_socks: slotmap::SecondaryMap::new(),
            has_address: HashSet::new(),
            last_routes: Vec::new(),
            last_mst: Vec::new(),
            mac_table: HashMap::new(),
            mac_leases: mac_lease::MacLeases::default(),
            age_subnets_timer: None,
            dns,
            settings,
            // Set true by `device_enable()` after this struct is
            // built (when `!device_standby`); else false until the
            // first BecameReachable.
            device_enabled: false,
            invitation_key,
            // First SIGHUP compares against this. The delta to "end
            // of setup" is one event-loop turn (~ms).
            last_config_check: SystemTime::now(),
            ev,
            timers,
            signals,
            pingtimer,
            age_timer,
            periodictimer,
            keyexpire_timer,
            running: true,
            any_pcap: false,
            discovery: None,
            dht_hints: HashMap::new(),
            dht_probe_sent: HashSet::new(),
        };

        // ─── try_outgoing_connections - the actual setup
        // Done HERE (not above) because it needs `&mut self` for the
        // slotmap + graph + EventLoop.
        for peer in connect_to {
            // The node goes into the graph BEFORE we connect; an
            // ADD_EDGE arriving via some OTHER path can find it.
            daemon.lookup_or_add_node(&peer);
            let config_addrs = resolve_config_addrs(&daemon.confbase, &peer);
            let addr_cache =
                crate::addrcache::AddressCache::open(&daemon.confbase, &peer, config_addrs);
            let oid = daemon.outgoings.insert(Outgoing {
                node_name: peer,
                timeout: 0,
                addr_cache,
            });
            // Disarmed; `retry_outgoing` arms it.
            let tid = daemon.timers.add(TimerWhat::RetryOutgoing(oid));
            daemon.outgoing_timers.insert(oid, tid);
            daemon.setup_outgoing_connection(oid);
        }

        // The mark-sweep (terminate connections whose ConnectTo was
        // removed) is in `reload_configuration`. setup() never has
        // stale outgoings (it's first boot).

        // ─── load_all_nodes
        // Done after the ConnectTo loop - both add to the same
        // graph, order doesn't matter for correctness, but doing it
        // last keeps the "load every name from disk" step in one place.
        daemon.load_all_nodes();

        // ─── DHT discovery spawn (Rust extension). After listeners
        // (need `my_udp_port` resolved). Spawn failure is non-fatal.
        if daemon.settings.dht_discovery {
            // SigningKey doesn't impl Clone by design.
            let key = SigningKey::from_blob(&daemon.mykey.to_blob());
            let bootstrap = if daemon.settings.dht_bootstrap.is_empty() {
                None
            } else {
                Some(daemon.settings.dht_bootstrap.as_slice())
            };
            match crate::discovery::Discovery::spawn(key, daemon.my_udp_port, bootstrap) {
                Ok(d) => {
                    log::info!(target: "tincd::discovery",
                    "DHT discovery enabled (port {}, bootstrap: {})",
                    daemon.my_udp_port,
                    bootstrap.map_or(
                        "mainline".to_owned(),
                        |b| b.join(", ")
                    ));
                    daemon.discovery = Some(d);
                }
                Err(e) => {
                    log::warn!(target: "tincd::discovery",
                               "DHT actor spawn failed (continuing \
                                without): {e}");
                }
            }
        }

        // ─── tinc-up
        // The script typically does `ip addr add` / `ip link set up`
        // on the TUN. Base env only (no NODE/SUBNET). When standby,
        // the FIRST BecameReachable in `run_graph_and_log` fires it
        // instead.
        if !daemon.settings.device_standby {
            daemon.device_enable();
        }

        // Fire subnet-up for our OWN configured subnets. AFTER
        // tinc-up: subnet-up scripts (which add routes) assume the
        // iface is configured. Same loop shape as the BecameReachable
        // arm in gossip.rs.
        for s in &daemon.subnets.owned_by(&daemon.name) {
            daemon.run_subnet_script(true, &daemon.name, s);
        }

        Ok(daemon)
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
    /// and we always re-arm. mio handles `None` correctly.
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
                        // write/read dispatch - the WRITE edge that
                        // woke us is the SAME edge that lets us flush
                        // the ID line. mio is EDGE-triggered: if we
                        // `continue` here, the next WRITE wake never
                        // comes (the socket was already writable when
                        // we queued the ID). Probe-spurious and
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
    /// to global.
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
        // Unparseable port → default. We don't support service-name
        // resolution; fall back.
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
    #[test]
    fn build_listeners_two_bindto_shares_port() {
        // Two distinct loopback addrs. Linux routes the whole
        // 127.0.0.0/8 to lo; binding 127.42.x.x works without
        // setup. Avoid 127.0.0.x - the integration tests'
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
    /// `bindto` flag.
    #[test]
    fn build_listeners_bindto_vs_listen() {
        let cfg = cfg_from(&["BindToAddress = 127.42.1.1", "ListenAddress = 127.42.1.2"]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 2);
        // BindToAddress walked first.
        assert!(ls[0].bindto, "BindToAddress → bindto=true");
        assert!(!ls[1].bindto, "ListenAddress → bindto=false");
    }

    /// `BindToAddress = *` → wildcard.
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

    /// Duplicate addresses skipped.
    #[test]
    fn build_listeners_dedups() {
        let cfg = cfg_from(&[
            "BindToAddress = 127.42.2.1",
            "BindToAddress = 127.42.2.1", // duplicate
        ]);
        let ls = build_listeners(&cfg, 0, AddrFamily::Ipv4, &SockOpts::default());
        assert_eq!(ls.len(), 1, "duplicate skipped");
    }

    /// `DaemonSettings::default()` matches upstream tinc defaults.
    #[test]
    fn settings_defaults_match_c() {
        let s = DaemonSettings::default();
        assert_eq!(s.pinginterval, 60);
        assert_eq!(s.pingtimeout, 5);
        assert_eq!(s.port, 655);
        assert_eq!(s.addressfamily, AddrFamily::Any);
        assert_eq!(s.udp_discovery_timeout, 30);
        assert_eq!(s.compression, 0);
        assert!(!s.tunnelserver);
        assert!(!s.strictsubnets);
        assert!(s.bind_to_address.is_none());
        assert!(s.local_discovery);
        assert!(!s.directonly);
        assert!(!s.priorityinheritance);
        assert_eq!(s.forwarding_mode, ForwardingMode::Internal);
        assert!(s.autoconnect);
        assert_eq!(s.udp_info_interval, 5);
        assert_eq!(s.mtu_info_interval, 5);
        assert_eq!(s.maxoutbufsize, 10 * MTU as usize);
        assert_eq!(s.sockopts.udp_rcvbuf, 1024 * 1024);
        assert_eq!(s.sockopts.udp_sndbuf, 1024 * 1024);
        assert_eq!(s.sockopts.fwmark, 0);
        assert_eq!(s.replaywin, 32);
        assert_eq!(s.max_connection_burst, 10);
        assert!(s.udp_discovery);
        assert!(!s.device_standby);
        assert!(s.scripts_interpreter.is_none());
        assert!(s.global_pmtu.is_none());
        assert!(s.global_weight.is_none());
    }

    /// Rate limit on the Unreachable arm. Max 3/sec. Can't
    /// construct a full `Daemon` (SelfPipe singleton); test the
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
    /// full `Daemon` (SelfPipe is process-singleton); test the math
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

    /// The IoWhat enum has all six variants. Compile-time check:
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

    /// `expand_name` $-expansion + sanitize.
    #[test]
    fn expand_name_passthrough() {
        // No `$` prefix → returned as-is, NO sanitization. Only
        // the env-expanded branch is sanitized; literal Name goes
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
        // Non-alnum → `_`.
        assert_eq!(expand_name("$TINC_TEST_NAME_DOTTED").unwrap(), "host_local");
        assert_eq!(expand_name("$TINC_TEST_NAME_DASHED").unwrap(), "my_host");
    }

    #[test]
    fn expand_name_unset_var_errors() {
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
        //      survived (stripped at first `.` then sanitized)
        // If $HOST happens to be set in env, that path is exercised
        // instead - same postconditions hold.
        let n = expand_name("$HOST").unwrap();
        assert!(!n.is_empty());
        assert!(n.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }
}
